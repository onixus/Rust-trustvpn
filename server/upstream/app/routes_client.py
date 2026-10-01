"""Клиентская часть: /login, /register, /dashboard, конфиги, сброс пароля, скачивание."""
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, RedirectResponse, Response)

from . import conninfo, db, endpoint, mailer, qr, security, webauth
from .templating import templates

router = APIRouter()

# Установщик Windows-приложения кладётся в персистентный том /data
# (на хосте — /opt/trusttunnel-web/data/downloads/). Обновляется заливкой файла,
# без пересборки контейнера.
WIN_INSTALLER = os.environ.get("WIN_INSTALLER", "/data/downloads/TrustTunnel-Setup.exe")
ANDROID_APK = os.environ.get("ANDROID_APK", "/data/downloads/TrustTunnel.apk")
# Отдельная сборка под armv7: старые телефоны. Ядро туннеля — статический бинарь
# под конкретную архитектуру, одной сборкой обе не покрыть без лишних мегабайт.
ANDROID_APK_V7 = os.environ.get("ANDROID_APK_V7", "/data/downloads/TrustTunnel-armv7.apk")

# Контрольная сумма APK: телефон ставится мимо магазина, и возможность сверить
# файл — единственный способ убедиться, что скачалось именно наше. Считаем один
# раз на файл (ключ — размер и время правки), иначе каждый показ кабинета хешировал
# бы двадцать мегабайт.
_sha_cache: dict[tuple, str] = {}


def _sha256(path: str) -> str | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_size, st.st_mtime_ns)
    if key not in _sha_cache:
        import hashlib

        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        _sha_cache.clear()
        _sha_cache[key] = h.hexdigest()
    return _sha_cache[key]


def _brand() -> str:
    return db.get_setting("brand_name", "TrustTunnel")


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    settings = db.get_settings()
    configs = [conninfo.connection_info(c, settings) | {"id": c["id"]}
               for c in db.list_user_configs(user["id"])]
    return templates.TemplateResponse(
        request, "dashboard.html",
        {
            "brand": _brand(), "user": user, "configs": configs,
            "devices": db.list_user_devices(user["id"]),
            "endpoint_ready": bool(endpoint.effective_domain(settings)),
            "win_app": os.path.exists(WIN_INSTALLER),
            "android_app": os.path.exists(ANDROID_APK),
            "android_sha256": _sha256(ANDROID_APK),
            "android_v7": os.path.exists(ANDROID_APK_V7),
            "error": request.query_params.get("error"),
        },
    )


# ── привязка устройства по QR ────────────────────────────────────────────────

ENROLL_TTL_SECONDS = 180


@router.post("/devices/enroll-qr", response_class=HTMLResponse)
def device_enroll_qr(request: Request):
    """Выдаёт одноразовый код привязки и рисует его QR прямо в странице.

    Код показывается ровно один раз (в базе только его sha256) и живёт минуты.
    В QR кладём ссылку на этот же сервер: приложение берёт из неё и адрес панели,
    и код — на телефоне ничего вводить руками не нужно.
    """
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)

    db.purge_expired_enroll_codes()
    raw = security.new_token(24)
    db.create_enroll_code(user["id"], security.hash_api_token(raw), ENROLL_TTL_SECONDS)

    # portal_url, как и в письмах: за обратным прокси request.base_url отдаёт
    # http-схему внутреннего порта, и приложение упиралось бы в редирект (301).
    base = (db.get_setting("portal_url") or str(request.base_url)).rstrip("/")
    # Код во фрагменте: он не попадает в логи сервера и в Referer, если ссылку
    # всё же откроют браузером.
    link = f"{base}/e#{raw}"
    # Своя схема — для случая, когда кабинет открыт на самом телефоне: нажатие
    # открывает приложение и привязывает устройство без компьютера и без камеры.
    # Адрес сервера приходится передавать явно: у своей схемы нет origin.
    app_link = f"ttsuperlink://enroll?server={quote(base, safe='')}#{raw}"
    return templates.TemplateResponse(
        request, "device_qr.html",
        {
            "brand": _brand(), "user": user,
            "qr_svg": qr.svg(link),
            "link": link,
            "app_link": app_link,
            "ttl": ENROLL_TTL_SECONDS,
        },
    )


@router.post("/devices/{device_id}/revoke")
def device_revoke(request: Request, device_id: int):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    device = db.get_device(device_id)
    if device is None or device["user_id"] != user["id"]:
        return RedirectResponse("/?error=Устройство+не+найдено", 302)
    db.revoke_device(device_id)
    endpoint.manager.apply_credentials()
    return RedirectResponse("/", 302)


@router.get("/.well-known/assetlinks.json")
def assetlinks():
    """Подтверждает Android, что ссылки /e на этом домене принадлежат приложению.

    Без этого файла система не «верифицирует» ссылку и показывает выбор приложения —
    работать будет, но менее гладко. Отпечаток подписи держим в настройках: при
    выпуске релизного ключа его меняют без пересборки образа.

    Формат отпечатка — как у Google: HEX-байты через двоеточие в верхнем регистре.
    """
    fp = (db.get_setting("android_cert_sha256") or "").strip()
    pkg = (db.get_setting("android_package") or "kz.servername.trusttunnel").strip()
    if not fp:
        return JSONResponse([], status_code=404)

    prints = []
    for item in fp.replace(",", " ").split():
        raw = item.replace(":", "").strip()
        if len(raw) == 64:
            prints.append(":".join(raw[i:i + 2] for i in range(0, 64, 2)).upper())
    if not prints:
        return JSONResponse([], status_code=404)

    return JSONResponse([{
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {
            "namespace": "android_app",
            "package_name": pkg,
            "sha256_cert_fingerprints": prints,
        },
    }])


@router.get("/e", response_class=HTMLResponse)
def enroll_landing(request: Request):
    """Куда попадает тот, кто открыл QR-ссылку браузером, а не приложением.

    Сам код лежит во фрагменте URL и до сервера не доходит — страница только
    объясняет, что делать.
    """
    return templates.TemplateResponse(
        request, "enroll_landing.html", {"brand": _brand()},
    )


@router.get("/download/windows")
def download_windows(request: Request):
    """Отдать установщик Windows-приложения (лежит в томе /data).

    Имя файла — TrustTunnel-Setup_<хост>.exe: установщик достаёт из него адрес и
    кладёт рядом с приложением, чтобы скачавшему не пришлось вписывать адрес
    руками. Схему в имя не положить («:» и «/» в именах файлов запрещены), поэтому
    передаём только хост, а «https://» дописывает установщик.
    """
    if not os.path.exists(WIN_INSTALLER):
        raise HTTPException(404, "Установщик ещё не загружен администратором")
    base = (db.get_setting("portal_url") or str(request.base_url)).rstrip("/")
    host = urlparse(base).hostname or ""
    name = f"TrustTunnel-Setup_{host}.exe" if host else "TrustTunnel-Setup.exe"
    return FileResponse(
        WIN_INSTALLER, media_type="application/octet-stream", filename=name,
    )


@router.get("/download/android")
def download_android():
    """Отдать APK (лежит в томе /data, как и установщик Windows).

    Тип application/vnd.android.package-archive — чтобы телефон предложил
    установку, а не открыл файл как неизвестный.
    """
    if not os.path.exists(ANDROID_APK):
        raise HTTPException(404, "Приложение ещё не загружено администратором")
    return FileResponse(
        ANDROID_APK, media_type="application/vnd.android.package-archive",
        filename="TrustTunnel.apk",
    )


@router.get("/download/android-armv7")
def download_android_v7():
    """Сборка для старых телефонов (32-битный ARM)."""
    if not os.path.exists(ANDROID_APK_V7):
        raise HTTPException(404, "Сборка для armv7 ещё не загружена администратором")
    return FileResponse(
        ANDROID_APK_V7, media_type="application/vnd.android.package-archive",
        filename="TrustTunnel-armv7.apk",
    )


def _safe_next(nxt: str | None) -> str:
    """Только локальный путь: защита от open-redirect через ?next=."""
    if nxt and nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return "/"


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = ""):
    return templates.TemplateResponse(
        request, "login.html",
        {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
         "error": None, "msg": request.query_params.get("msg"), "next": next},
    )


@router.post("/login")
def login(request: Request, email: str = Form(), password: str = Form(), next: str = Form("")):
    user = db.get_user_by_email(email)
    if user is None or not security.verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Неверный e-mail или пароль", "msg": None, "next": next},
            status_code=401,
        )
    if user["status"] == "pending":
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Ваш аккаунт ожидает подтверждения администратором", "msg": None, "next": next},
            status_code=403,
        )
    elif user["status"] != "active":
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Аккаунт заблокирован", "msg": None, "next": next},
            status_code=403,
        )
    resp = RedirectResponse(_safe_next(next), 302)
    resp.set_cookie(
        webauth.USER_COOKIE, security.create_session_token(str(user["id"]), "user"),
        httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30,
    )
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    if db.get_setting("registration_enabled") != "1":
        return RedirectResponse("/login", 302)
    import random
    import hashlib
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    ans = a + b
    salt = "trusttunnel-captcha-salt"
    h = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
    resp = templates.TemplateResponse(
        request, "register.html",
        {"brand": _brand(), "error": None, "captcha_a": a, "captcha_b": b},
    )
    resp.set_cookie("captcha_hash", h, max_age=300, httponly=True, samesite="lax")
    return resp


@router.post("/register")
def register(request: Request, email: str = Form(), password: str = Form(), captcha: str = Form()):
    if db.get_setting("registration_enabled") != "1":
        return RedirectResponse("/login", 302)
    import random
    import hashlib

    # Верификация капчи
    cookie_hash = request.cookies.get("captcha_hash")
    salt = "trusttunnel-captcha-salt"
    user_hash = hashlib.sha256(f"{captcha.strip()}-{salt}".encode()).hexdigest()
    if not cookie_hash or user_hash != cookie_hash:
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        ans = a + b
        new_hash = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
        resp = templates.TemplateResponse(
            request, "register.html",
            {"brand": _brand(), "error": "Неверный ответ на проверочный вопрос", "captcha_a": a, "captcha_b": b},
            status_code=400,
        )
        resp.set_cookie("captcha_hash", new_hash, max_age=300, httponly=True, samesite="lax")
        return resp

    email = email.strip().lower()
    if len(password) < 6:
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        ans = a + b
        new_hash = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
        resp = templates.TemplateResponse(
            request, "register.html",
            {"brand": _brand(), "error": "Пароль слишком короткий (мин. 6)", "captcha_a": a, "captcha_b": b},
            status_code=400,
        )
        resp.set_cookie("captcha_hash", new_hash, max_age=300, httponly=True, samesite="lax")
        return resp

    if db.get_user_by_email(email):
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        ans = a + b
        new_hash = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
        resp = templates.TemplateResponse(
            request, "register.html",
            {"brand": _brand(), "error": "Такой e-mail уже зарегистрирован", "captcha_a": a, "captcha_b": b},
            status_code=400,
        )
        resp.set_cookie("captcha_hash", new_hash, max_age=300, httponly=True, samesite="lax")
        return resp

    db.create_user(email, security.hash_password(password), status="pending")
    resp = RedirectResponse("/login?msg=Регистрация успешна. Ожидайте подтверждения аккаунта администратором.", 302)
    resp.delete_cookie("captcha_hash")
    return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse("/login", 302)
    resp.delete_cookie(webauth.USER_COOKIE)
    return resp


@router.get("/forgot", response_class=HTMLResponse)
def forgot_form(request: Request):
    return templates.TemplateResponse(request, "forgot.html", {"brand": _brand(), "sent": False})


@router.post("/forgot")
def forgot(request: Request, email: str = Form()):
    email = email.strip().lower()
    user = db.get_user_by_email(email)
    if user is not None:
        token = security.new_token(16)
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        db.create_email_token(token, user["id"], "reset", expires)
        base = (db.get_setting("portal_url") or str(request.base_url).rstrip("/")).rstrip("/")
        link = f"{base}/reset?token={token}"
        if mailer.is_configured():
            try:
                mailer.send_mail(email, f"Сброс пароля — {_brand()}",
                                 f"Для сброса пароля перейдите по ссылке (действует 24 часа):\n\n{link}\n")
            except Exception as e:  # не палим наличие аккаунта, но логируем
                print(f"[mail] reset send failed for {email}: {e}")
        else:
            print(f"[mail] SMTP не настроен. Ссылка сброса для {email}: {link}")
    # Ответ одинаков независимо от наличия аккаунта.
    return templates.TemplateResponse(request, "forgot.html", {"brand": _brand(), "sent": True, "email": email})


@router.get("/reset", response_class=HTMLResponse)
def reset_form(request: Request, token: str = ""):
    return templates.TemplateResponse(
        request, "reset.html", {"brand": _brand(), "token": token, "error": None, "done": False},
    )


@router.post("/reset")
def reset(request: Request, token: str = Form(), password: str = Form()):
    row = db.get_email_token(token)
    ctx = {"brand": _brand(), "token": token, "error": None, "done": False}
    if not row or row["purpose"] != "reset" or row["expires_at"] < datetime.now(timezone.utc).isoformat():
        ctx["error"] = "Ссылка недействительна или устарела"
        return templates.TemplateResponse(request, "reset.html", ctx, status_code=400)
    if len(password) < 6:
        ctx["error"] = "Пароль слишком короткий (мин. 6)"
        return templates.TemplateResponse(request, "reset.html", ctx, status_code=400)
    db.set_user_password(row["user_id"], security.hash_password(password))
    db.delete_email_token(token)
    return templates.TemplateResponse(
        request, "reset.html", {"brand": _brand(), "token": "", "error": None, "done": True},
    )


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return RedirectResponse("/", 302)


@router.post("/configs")
def create_config(request: Request, label: str = Form("")):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    suffix = security.new_token(4)
    db.create_config(
        user["id"],
        tt_username=f"u{user['id']}-{suffix}",
        tt_password=security.new_token(9),
        label=label.strip() or None,
    )
    endpoint.manager.apply_credentials()
    return RedirectResponse("/", 302)


@router.post("/configs/{config_id}/delete")
def delete_config(request: Request, config_id: int):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    cfg = db.get_config(config_id)
    if cfg and cfg["user_id"] == user["id"]:
        db.delete_config(config_id)
        endpoint.manager.apply_credentials()
    return RedirectResponse("/", 302)


@router.get("/config/{config_id}/download")
def download_config(request: Request, config_id: int, fmt: str = "txt"):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    cfg = db.get_config(config_id)
    if not cfg or cfg["user_id"] != user["id"]:
        return PlainTextResponse("Not found", status_code=404)
    info = conninfo.connection_info(cfg, db.get_settings())
    raw_name = cfg["label"] or cfg["tt_username"]
    safe = "".join(ch for ch in raw_name if ch.isascii() and (ch.isalnum() or ch in "-_")) or cfg["tt_username"]
    if fmt == "toml":
        from .client_config import build_client_toml
        body, media, ext = build_client_toml(info), "text/plain", "toml"
    elif fmt == "json":
        body, media, ext = conninfo.as_download_json(info), "application/json", "json"
    else:
        body, media, ext = conninfo.as_download_text(info, _brand()), "text/plain; charset=utf-8", "txt"
    return Response(
        content=body, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="trusttunnel-{safe}.{ext}"'},
    )

"""Контракт Windows-клиента для одно-нодовой вебы.

Тот же API, что у trusttunnel-panel (форк — копия, не общий код), поэтому один и
тот же бинарь приложения работает и здесь: достаточно указать в приложении адрес
этой вебы.

Два контура авторизации:
- страница /connect — веб-логин (cookie), выпуск device-token, редирект на loopback;
- /portal/v1/device/* — работа устройства по X-Device-Token.
"""
from urllib.parse import quote, urlencode, urlparse

from fastapi import APIRouter, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from . import client_config, conninfo, db, endpoint, security, webauth
from .templating import templates

router = APIRouter()


def _brand() -> str:
    return db.get_setting("brand_name", "TrustTunnel")


def _device_from_header(x_device_token: str | None):
    """X-Device-Token → строка устройства. Отозванное/чужой юзер → 401/403."""
    if not x_device_token:
        raise HTTPException(401, "Требуется токен устройства")
    device = db.get_device_by_token_hash(security.hash_api_token(x_device_token))
    if device is None or device["revoked_at"] is not None:
        raise HTTPException(401, "Устройство не найдено или отозвано")
    user = db.get_user(device["user_id"])
    if user is None or user["status"] != "active":
        raise HTTPException(403, "Аккаунт заблокирован или ожидает подтверждения")
    db.touch_device(device["id"])
    return device, user


# ── Веб-авторизация устройства (страница) ────────────────────────────────────

def _is_loopback(uri: str) -> bool:
    try:
        p = urlparse(uri)
    except ValueError:
        return False
    return p.scheme in ("http", "https") and p.hostname in ("127.0.0.1", "localhost", "::1")


@router.get("/connect", response_class=HTMLResponse)
def connect_page(request: Request, redirect_uri: str = "", state: str = "", name: str = "Windows PC"):
    if not _is_loopback(redirect_uri):
        return templates.TemplateResponse(
            request, "connect.html",
            {"brand": _brand(), "ok": False, "error": "Недопустимый redirect_uri (только 127.0.0.1)"},
            status_code=400,
        )
    if not webauth.current_user(request):
        nxt = "/connect?" + urlencode({"redirect_uri": redirect_uri, "state": state, "name": name})
        return RedirectResponse("/login?next=" + quote(nxt, safe=""), 302)
    return templates.TemplateResponse(
        request, "connect.html",
        {"brand": _brand(), "ok": True, "error": None,
         "redirect_uri": redirect_uri, "state": state, "name": name},
    )


@router.get("/connect/done", response_class=HTMLResponse)
def connect_done():
    """Куда приложение уводит браузер после успешного входа — чтобы не оставлять
    loopback-URL с токеном в адресной строке. Публичная, без данных."""
    return HTMLResponse(
        "<!doctype html><html lang=ru><head><meta charset=utf-8>"
        "<title>Готово</title><style>body{font-family:system-ui;background:#0f1115;"
        "color:#e6e8ec;display:flex;height:100vh;margin:0;align-items:center;"
        "justify-content:center;text-align:center}</style></head><body><div>"
        "<h2>Устройство подключено</h2>"
        "<p>Можно закрыть эту вкладку и вернуться в приложение TrustTunnel.</p>"
        "<script>setTimeout(function(){try{window.close()}catch(e){}},800)</script>"
        "</div></body></html>"
    )


@router.post("/connect/approve")
def connect_approve(
    request: Request,
    redirect_uri: str = Form(),
    state: str = Form(""),
    name: str = Form("Windows PC"),
):
    if not _is_loopback(redirect_uri):
        return templates.TemplateResponse(
            request, "connect.html",
            {"brand": _brand(), "ok": False, "error": "Недопустимый redirect_uri"},
            status_code=400,
        )
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    raw = security.new_token(32)
    db.create_device(user["id"], name.strip() or "Windows PC", security.hash_api_token(raw))
    sep = "&" if urlparse(redirect_uri).query else "?"
    return RedirectResponse(redirect_uri + sep + urlencode({"token": raw, "state": state}), 302)


# ── API устройства (X-Device-Token) ──────────────────────────────────────────

@router.get("/portal/v1/device/me")
def device_me(x_device_token: str | None = Header(default=None)):
    device, user = _device_from_header(x_device_token)
    return {"device_id": device["id"], "name": device["name"], "user_email": user["email"]}


@router.get("/portal/v1/device/locations")
def device_locations(x_device_token: str | None = Header(default=None)):
    """Одно-нодовая веба: одна синтетическая локация."""
    _device_from_header(x_device_token)
    return [{"group_id": 1, "slug": "default", "name": db.get_setting("brand_name", "Основной сервер")}]


class EnrollIn(BaseModel):
    code: str
    name: str = "Телефон"
    platform: str = "android"


@router.post("/portal/v1/device/enroll")
def device_enroll(data: EnrollIn):
    """Привязка устройства по одноразовому коду из QR.

    Токен в QR не кладём: код одноразовый и живёт минуты, поэтому снимок чужого
    экрана даёт лишь узкое окно, а привязанное устройство видно в кабинете и
    отзывается одной кнопкой.
    """
    code = (data.code or "").strip()
    if not code:
        raise HTTPException(400, "Пустой код")

    row = db.consume_enroll_code(security.hash_api_token(code))
    if row is None:
        # Не разделяем «нет такого» / «истёк» / «уже использован» — незачем
        # подсказывать подбирающему, насколько он близок.
        raise HTTPException(400, "Код недействителен или истёк")

    user = db.get_user(row["user_id"])
    if user is None or user["status"] != "active":
        raise HTTPException(403, "Аккаунт заблокирован или ожидает подтверждения")

    raw = security.new_token(32)
    name = (data.name or "").strip()[:64] or "Телефон"
    platform = (data.platform or "").strip()[:16] or "android"
    device_id = db.create_device(user["id"], name, security.hash_api_token(raw), platform)
    db.attach_enroll_device(row["code_hash"], device_id)
    return {"token": raw, "device_id": device_id, "user_email": user["email"]}


class ConnectIn(BaseModel):
    group_id: int = 1
    killswitch: bool = False


@router.post("/portal/v1/device/connect")
def device_connect(data: ConnectIn, x_device_token: str | None = Header(default=None)):
    device, user = _device_from_header(x_device_token)

    settings = db.get_settings()
    if not endpoint.effective_domain(settings):
        raise HTTPException(409, "Сервер ещё не настроен (нет домена/сертификата)")

    cfg = db.get_device_config(device["id"])
    if cfg is None:
        suffix = security.new_token(4)
        cfg_id = db.create_device_config(
            user["id"], device["id"],
            tt_username=f"u{user['id']}-{suffix}",
            tt_password=security.new_token(9),
            label=device["name"],
        )
        endpoint.manager.apply_credentials()  # endpoint подхватит новый cred
        cfg = db.get_config(cfg_id)

    info = conninfo.connection_info(cfg, settings)
    toml = client_config.build_client_toml(info, killswitch=data.killswitch)
    return JSONResponse({
        "config_id": cfg["id"],
        "location": db.get_setting("brand_name", "Основной сервер"),
        "client_toml": toml,
    })

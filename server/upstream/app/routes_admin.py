"""Админка /admin: единственная роль. Управление пользователями, конфигами, настройками."""
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import conninfo, db, endpoint, security, webauth, mailer, config_mail
from .templating import templates

router = APIRouter(prefix="/admin")


def _brand() -> str:
    return db.get_setting("brand_name", "TrustTunnel")


def _ctx(request: Request, admin, **extra) -> dict:
    base = {"brand": _brand(), "admin": admin, "counts": db.counts()}
    base.update(extra)
    return base


# ── Аутентификация ───────────────────────────────────────────────────────────
@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    if webauth.current_admin(request):
        return RedirectResponse("/admin/dashboard", 302)
    return RedirectResponse("/admin/login", 302)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(request, "admin_login.html", {"brand": _brand(), "error": None})


@router.post("/login")
def login(request: Request, email: str = Form(), password: str = Form()):
    admin = db.get_admin_by_email(email)
    if admin is None or not security.verify_password(password, admin["password_hash"]):
        return templates.TemplateResponse(
            request, "admin_login.html", {"brand": _brand(), "error": "Неверный вход"}, status_code=401,
        )
    resp = RedirectResponse("/admin/dashboard", 302)
    resp.set_cookie(
        webauth.ADMIN_COOKIE, security.create_session_token(str(admin["id"]), "admin"),
        httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30,
    )
    return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse("/admin/login", 302)
    resp.delete_cookie(webauth.ADMIN_COOKIE)
    return resp


# ── Дашборд ──────────────────────────────────────────────────────────────────
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    return templates.TemplateResponse(
        request, "admin_dashboard.html",
        _ctx(request, admin, status=endpoint.manager.status(),
             msg=request.query_params.get("msg"), err=request.query_params.get("err")),
    )


# ── Пользователи ─────────────────────────────────────────────────────────────
@router.get("/users", response_class=HTMLResponse)
def users(request: Request):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    return templates.TemplateResponse(
        request, "admin_users.html",
        _ctx(request, admin, users=db.list_users(),
             msg=request.query_params.get("msg"), err=request.query_params.get("err")),
    )


@router.post("/users/create")
def create_user(request: Request, email: str = Form(), password: str = Form()):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    email = email.strip().lower()
    if db.get_user_by_email(email):
        return RedirectResponse("/admin/users?err=E-mail уже существует", 302)
    if len(password) < 6:
        return RedirectResponse("/admin/users?err=Пароль слишком короткий", 302)
    db.create_user(email, security.hash_password(password))
    return RedirectResponse("/admin/users?msg=Пользователь создан", 302)


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(request: Request, user_id: int):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    user = db.get_user(user_id)
    if not user:
        return RedirectResponse("/admin/users?err=Не найден", 302)
    settings = db.get_settings()
    configs = [conninfo.connection_info(c, settings) | {"id": c["id"]}
               for c in db.list_user_configs(user_id)]
    return templates.TemplateResponse(
        request, "admin_user_detail.html",
        _ctx(request, admin, user=user, configs=configs,
             mail_token=config_mail.token(request.cookies.get(webauth.ADMIN_COOKIE, ""), user_id),
             mail_ready=mailer.is_configured(),
             msg=request.query_params.get("msg"), err=request.query_params.get("err")),
    )


@router.post("/users/{user_id}/password")
def user_password(request: Request, user_id: int, password: str = Form()):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    if len(password) < 6:
        return RedirectResponse(f"/admin/users/{user_id}?err=Пароль слишком короткий", 302)
    db.set_user_password(user_id, security.hash_password(password))
    return RedirectResponse(f"/admin/users/{user_id}?msg=Пароль обновлён", 302)


@router.post("/users/{user_id}/email")
def user_email(request: Request, user_id: int, email: str = Form()):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    db.set_user_email(user_id, email)
    return RedirectResponse(f"/admin/users/{user_id}?msg=E-mail обновлён", 302)


@router.post("/users/{user_id}/status")
def user_status(request: Request, user_id: int, status: str = Form()):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    db.set_user_status(user_id, "blocked" if status == "blocked" else "active")
    endpoint.manager.apply_credentials()  # снять/вернуть креды заблокированного
    return RedirectResponse(f"/admin/users/{user_id}?msg=Статус обновлён", 302)


# ── Администраторы ────────────────────────────────────────────────────────────
@router.get("/admins", response_class=HTMLResponse)
def admins_list(request: Request):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    return templates.TemplateResponse(
        request, "admin_admins.html",
        _ctx(request, admin, admins=db.list_admins(),
             msg=request.query_params.get("msg"), err=request.query_params.get("err")),
    )


@router.post("/admins/create")
def create_admin(request: Request, email: str = Form(), recovery_email: str = Form(None), password: str = Form()):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    email = email.strip().lower()
    recovery_email = recovery_email.strip().lower() if recovery_email else None
    if db.get_admin_by_email(email):
        return RedirectResponse("/admin/admins?err=Администратор уже существует", 302)
    if len(password) < 8:
        return RedirectResponse("/admin/admins?err=Пароль слишком короткий (мин. 8)", 302)
    db.create_admin(email, recovery_email, security.hash_password(password))
    return RedirectResponse("/admin/admins?msg=Администратор создан", 302)


@router.post("/admins/{admin_id}/password")
def change_admin_password(request: Request, admin_id: int, password: str = Form()):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    if len(password) < 8:
        return RedirectResponse("/admin/admins?err=Пароль слишком короткий (мин. 8)", 302)
    db.set_admin_password(admin_id, security.hash_password(password))
    return RedirectResponse("/admin/admins?msg=Пароль администратора изменен", 302)


@router.post("/admins/{admin_id}/delete")
def delete_admin(request: Request, admin_id: int):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    if admin["id"] == admin_id:
        return RedirectResponse("/admin/admins?err=Нельзя удалить самого себя", 302)
    db.delete_admin(admin_id)
    return RedirectResponse("/admin/admins?msg=Администратор удален", 302)


@router.post("/users/{user_id}/delete")
def user_delete(request: Request, user_id: int):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    db.delete_user(user_id)
    endpoint.manager.apply_credentials()
    return RedirectResponse("/admin/users?msg=Пользователь удалён", 302)


@router.post("/users/{user_id}/configs")
def user_create_config(request: Request, user_id: int, label: str = Form("")):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    user = db.get_user(user_id)
    if not user:
        return RedirectResponse("/admin/users?err=Не найден", 302)
    suffix = security.new_token(4)
    db.create_config(user_id, f"u{user_id}-{suffix}", security.new_token(9), label.strip() or None)
    endpoint.manager.apply_credentials()
    return RedirectResponse(f"/admin/users/{user_id}?msg=Конфиг создан", 302)


@router.post("/configs/{config_id}/delete")
def admin_delete_config(request: Request, config_id: int):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    cfg = db.get_config(config_id)
    db.delete_config(config_id)
    endpoint.manager.apply_credentials()
    target = f"/admin/users/{cfg['user_id']}" if cfg else "/admin/configs"
    return RedirectResponse(f"{target}?msg=Конфиг удалён", 302)


@router.get("/configs", response_class=HTMLResponse)
def all_configs(request: Request):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    return templates.TemplateResponse(
        request, "admin_configs.html", _ctx(request, admin, configs=db.list_all_configs()),
    )


# ── Настройки ────────────────────────────────────────────────────────────────
_SETTING_KEYS = [
    "brand_name", "cert_mode", "panel_domain", "connection_hidden", "conn_domain",
    "le_email", "conn_address", "conn_port", "conn_sni", "conn_protocol",
    "registration_enabled",
    "show_address", "show_port", "show_domain", "show_sni",
    "show_username", "show_password", "show_protocol",
    "smtp_host", "smtp_port", "smtp_user", "smtp_password",
    "smtp_from", "smtp_tls", "portal_url",
]
_CHECKBOX_KEYS = {
    "connection_hidden", "registration_enabled",
    "show_address", "show_port", "show_domain", "show_sni",
    "show_username", "show_password", "show_protocol",
}


@router.get("/settings", response_class=HTMLResponse)
def settings_form(request: Request):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    return templates.TemplateResponse(
        request, "admin_settings.html",
        _ctx(request, admin, s=db.get_settings(), cert_domains=endpoint.scan_cert_domains(),
             status=endpoint.manager.status(), cert_dir=endpoint.config.CERT_DIR,
             msg=request.query_params.get("msg"), err=request.query_params.get("err")),
    )


@router.post("/settings")
async def settings_save(request: Request):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    form = await request.form()
    updates: dict[str, str] = {}
    for key in _SETTING_KEYS:
        if key in _CHECKBOX_KEYS:
            updates[key] = "1" if form.get(key) else "0"
        elif key in form:
            updates[key] = str(form.get(key)).strip()
    db.set_settings(updates)
    endpoint.manager.apply_settings()  # применить домен/порт/серт к endpoint'у
    return RedirectResponse("/admin/settings?msg=Настройки сохранены", 302)


@router.post("/account/password")
def admin_password(request: Request, password: str = Form()):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    if len(password) < 8:
        return RedirectResponse("/admin/dashboard?err=Пароль слишком короткий (мин. 8)", 302)
    db.set_admin_password(admin["id"], security.hash_password(password))
    return RedirectResponse("/admin/dashboard?msg=Пароль администратора обновлён", 302)


@router.post("/account/profile")
def admin_profile(request: Request, email: str = Form(), recovery_email: str = Form(None)):
    admin = webauth.current_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", 302)
    email = email.strip().lower()
    recovery_email = recovery_email.strip().lower() if recovery_email else None

    # Проверить уникальность логина
    existing = db.get_admin_by_email(email)
    if existing and existing["id"] != admin["id"]:
        return RedirectResponse("/admin/dashboard?err=Логин уже занят другим администратором", 302)

    db.set_admin_recovery_email(admin["id"], recovery_email)

    # Обновить email (логин)
    with db.connect() as conn:
        conn.execute("UPDATE admins SET email = ? WHERE id = ?", (email, admin["id"]))

    return RedirectResponse("/admin/dashboard?msg=Профиль успешно обновлён", 302)


@router.post("/users/{user_id}/send-configs")
def email_configs(request: Request, user_id: int, mail_token: str = Form(""), config_id: int = Form(0)):
    if not webauth.current_admin(request):
        return RedirectResponse("/admin/login", 302)
    from fastapi import HTTPException
    from urllib.parse import urlencode
    if not config_mail.valid_token(request.cookies.get(webauth.ADMIN_COOKIE, ""), user_id, mail_token):
        raise HTTPException(status_code=403, detail="Invalid form token")
    try:
        count = config_mail.send(user_id, config_id)
        query = urlencode({"msg": f"Отправлено профилей: {count}. Письмо принято SMTP-сервером."})
    except config_mail.MailError as exc:
        query = urlencode({"err": str(exc)})
    return RedirectResponse(f"/admin/users/{user_id}?{query}", 303)

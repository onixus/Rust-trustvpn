"""Хелперы cookie-сессий для клиентской части и админки."""
import sqlite3

from fastapi import Request

from . import db, security

USER_COOKIE = "user_token"
ADMIN_COOKIE = "admin_token"


def current_user(request: Request) -> sqlite3.Row | None:
    tok = request.cookies.get(USER_COOKIE)
    if not tok:
        return None
    payload = security.decode_session_token(tok)
    if not payload or payload.get("kind") != "user":
        return None
    user = db.get_user(int(payload["sub"]))
    if user is None or user["status"] != "active":
        return None
    return user


def current_admin(request: Request) -> sqlite3.Row | None:
    tok = request.cookies.get(ADMIN_COOKIE)
    if not tok:
        return None
    payload = security.decode_session_token(tok)
    if not payload or payload.get("kind") != "admin":
        return None
    with db.connect() as conn:
        return conn.execute(
            "SELECT * FROM admins WHERE id = ?", (int(payload["sub"]),)
        ).fetchone()

"""Пароли (argon2 — совместимо с исходным trusttunnel-panel) и session-токены (JWT)."""
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from . import config

_ph = PasswordHasher()


def hash_password(raw: str) -> str:
    return _ph.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, raw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_api_token(raw: str) -> str:
    """SHA-256 для высокоэнтропийных токенов устройств (прямой поиск по колонке)."""
    import hashlib

    return hashlib.sha256(raw.encode()).hexdigest()


def create_session_token(subject: str, kind: str) -> str:
    """kind: 'admin' | 'user' — разделяет области авторизации."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "kind": kind,
        "iat": now,
        "exp": now + timedelta(minutes=config.ACCESS_TOKEN_TTL_MIN),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")


def decode_session_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

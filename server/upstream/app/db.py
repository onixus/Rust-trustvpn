"""Слой доступа к данным поверх stdlib sqlite3 (WAL). Никаких внешних БД."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from . import config, security

# ── Настройки по умолчанию (таблица settings — key/value) ────────────────────
DEFAULT_SETTINGS: dict[str, str] = {
    # Сертификаты / домены
    "cert_mode": "external",          # external | letsencrypt
    "panel_domain": "",               # домен, за которым живёт панель (домен A)
    "connection_hidden": "0",         # прятать подключение за отдельным доменом (домен B)
    "conn_domain": "",                # домен сертификата endpoint'а (что видит DPI)
    "le_email": "",                   # e-mail для Let's Encrypt (режим letsencrypt)
    # Параметры подключения, которые показываем клиенту
    "conn_address": "",               # host/IP сервера (пусто → panel_domain/PUBLIC_ADDRESS)
    "conn_port": "8443",
    "conn_sni": "",                   # custom SNI (пусто = не нужен)
    "conn_protocol": "QUIC",
    # Какие поля показывать клиенту в кабинете
    "show_address": "1",
    "show_port": "1",
    "show_domain": "1",
    "show_sni": "1",
    "show_username": "1",
    "show_password": "1",
    "show_protocol": "1",
    # Прочее
    "registration_enabled": "1",      # открытая регистрация в клиентской части
    "brand_name": "TrustTunnel",      # заголовок в интерфейсе
    # SMTP (для писем сброса пароля)
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_tls": "starttls",           # starttls | ssl | none
    "portal_url": "",                 # публичный URL панели для ссылок в письмах
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,            -- login
    recovery_email TEXT,                           -- recovery email
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',   -- active | blocked
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS configs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tt_username TEXT NOT NULL UNIQUE,
    tt_password TEXT NOT NULL,          -- plaintext: требование credentials.toml
    label       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at  TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS email_tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,          -- reset
    expires_at TEXT NOT NULL
);

-- Устройства Windows-клиента: тот же контракт, что у панели, но одно-нодовый.
CREATE TABLE IF NOT EXISTS app_devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,   -- sha256 от device-token
    platform     TEXT NOT NULL DEFAULT 'windows',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT,
    revoked_at   TEXT
);

-- Одноразовые коды привязки устройства по QR. Сам код не храним — только sha256,
-- как и device-токены: утечка базы не даёт привязать устройство.
CREATE TABLE IF NOT EXISTS enroll_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    device_id  INTEGER REFERENCES app_devices(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_configs_user   ON configs(user_id);
CREATE INDEX IF NOT EXISTS idx_configs_active ON configs(revoked_at);
CREATE INDEX IF NOT EXISTS idx_devices_user   ON app_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_enroll_expires ON enroll_codes(expires_at);
"""


@contextmanager
def connect():
    """Соединение с включёнными внешними ключами и Row-фабрикой."""
    conn = sqlite3.connect(config.DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Создать схему, включить WAL, засеять настройки и bootstrap-админа."""
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(_SCHEMA)
        try:
            conn.execute("ALTER TABLE admins ADD COLUMN recovery_email TEXT")
        except sqlite3.OperationalError:
            pass
        # Конфиг может быть привязан к устройству приложения (NULL = ручной).
        try:
            conn.execute("ALTER TABLE configs ADD COLUMN device_id INTEGER")
        except sqlite3.OperationalError:
            pass
        # Настройки: добавляем только отсутствующие ключи (не затираем правки админа).
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (key, value)
            )
        # Bootstrap-админ — если админов ещё нет.
        n = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
        if n == 0:
            conn.execute(
                "INSERT INTO admins(email, password_hash) VALUES (?, ?)",
                (
                    config.BOOTSTRAP_ADMIN_EMAIL.strip().lower(),
                    security.hash_password(config.BOOTSTRAP_ADMIN_PASSWORD),
                ),
            )


# ── Настройки ────────────────────────────────────────────────────────────────
def get_settings() -> dict[str, str]:
    with connect() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    merged = dict(DEFAULT_SETTINGS)
    merged.update({r["key"]: r["value"] for r in rows if r["value"] is not None})
    return merged


def get_setting(key: str, default: str = "") -> str:
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None or row["value"] is None:
        return DEFAULT_SETTINGS.get(key, default)
    return row["value"]


def set_settings(items: dict[str, str]) -> None:
    with connect() as conn:
        for key, value in items.items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )


# ── Админы ───────────────────────────────────────────────────────────────────
def get_admin_by_email(email: str) -> sqlite3.Row | None:
    with connect() as conn:
        val = email.strip().lower()
        return conn.execute(
            "SELECT * FROM admins WHERE email = ? OR recovery_email = ?", (val, val)
        ).fetchone()


def set_admin_password(admin_id: int, password_hash: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE admins SET password_hash = ? WHERE id = ?", (password_hash, admin_id)
        )


def list_admins() -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT id, email, recovery_email, created_at FROM admins ORDER BY id DESC").fetchall()


def create_admin(email: str, recovery_email: str | None, password_hash: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO admins(email, recovery_email, password_hash) VALUES (?, ?, ?)",
            (email.strip().lower(), recovery_email.strip().lower() if recovery_email else None, password_hash),
        )
        return cur.lastrowid


def set_admin_recovery_email(admin_id: int, recovery_email: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE admins SET recovery_email = ? WHERE id = ?",
            (recovery_email.strip().lower() if recovery_email else None, admin_id)
        )


def delete_admin(admin_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM admins WHERE id = ?", (admin_id,))


# ── Пользователи ─────────────────────────────────────────────────────────────
def get_user_by_email(email: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.strip().lower(),)
        ).fetchone()


def get_user(user_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(email: str, password_hash: str, status: str = "active") -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO users(email, password_hash, status) VALUES (?, ?, ?)",
            (email.strip().lower(), password_hash, status),
        )
        return cur.lastrowid


def list_users() -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT u.*, "
            "(SELECT COUNT(*) FROM configs c WHERE c.user_id = u.id AND c.revoked_at IS NULL) "
            "AS config_count "
            "FROM users u ORDER BY u.id DESC"
        ).fetchall()


def set_user_status(user_id: int, status: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))


def set_user_password(user_id: int, password_hash: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )


def set_user_email(user_id: int, email: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET email = ? WHERE id = ?", (email.strip().lower(), user_id)
        )


def delete_user(user_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── Конфиги ──────────────────────────────────────────────────────────────────
def create_config(user_id: int, tt_username: str, tt_password: str, label: str | None) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO configs(user_id, tt_username, tt_password, label) VALUES (?, ?, ?, ?)",
            (user_id, tt_username, tt_password, label),
        )
        return cur.lastrowid


def get_config(config_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM configs WHERE id = ?", (config_id,)).fetchone()


def list_user_configs(user_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM configs WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC",
            (user_id,),
        ).fetchall()


def list_all_configs() -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT c.*, u.email AS user_email FROM configs c "
            "JOIN users u ON u.id = c.user_id "
            "WHERE c.revoked_at IS NULL ORDER BY c.id DESC"
        ).fetchall()


def delete_config(config_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM configs WHERE id = ?", (config_id,))


def active_credentials() -> list[dict]:
    """Все креды активных конфигов активных (не заблокированных) юзеров → credentials.toml."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT c.tt_username AS username, c.tt_password AS password "
            "FROM configs c JOIN users u ON u.id = c.user_id "
            "WHERE c.revoked_at IS NULL AND u.status = 'active'"
        ).fetchall()
    return [{"username": r["username"], "password": r["password"]} for r in rows]


# ── Устройства приложения ────────────────────────────────────────────────────
def create_device(user_id: int, name: str, token_hash: str, platform: str = "windows") -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO app_devices(user_id, name, token_hash, platform) VALUES (?, ?, ?, ?)",
            (user_id, name, token_hash, platform),
        )
        return cur.lastrowid


def get_device(device_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM app_devices WHERE id = ?", (device_id,)
        ).fetchone()


def get_device_by_token_hash(token_hash: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM app_devices WHERE token_hash = ?", (token_hash,)
        ).fetchone()


def touch_device(device_id: int) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE app_devices SET last_seen_at = datetime('now') WHERE id = ?", (device_id,)
        )


def list_user_devices(user_id: int, include_revoked: bool = False) -> list[sqlite3.Row]:
    """Устройства пользователя. Отозванные по умолчанию скрыты: в кабинете они
    только копятся мусором, а доступа уже не дают (строки храним для истории)."""
    sql = "SELECT * FROM app_devices WHERE user_id = ?"
    if not include_revoked:
        sql += " AND revoked_at IS NULL"
    sql += " ORDER BY id DESC"
    with connect() as conn:
        return conn.execute(sql, (user_id,)).fetchall()


def get_device_config(device_id: int) -> sqlite3.Row | None:
    """Активный конфиг устройства (одно-нодовая веба — один конфиг на устройство)."""
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM configs WHERE device_id = ? AND revoked_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (device_id,),
        ).fetchone()


def create_device_config(
    user_id: int, device_id: int, tt_username: str, tt_password: str, label: str | None
) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO configs(user_id, device_id, tt_username, tt_password, label) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, device_id, tt_username, tt_password, label),
        )
        return cur.lastrowid


def create_enroll_code(user_id: int, code_hash: str, ttl_seconds: int) -> int:
    """Код привязки устройства (QR). Живёт минуты и срабатывает один раз."""
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO enroll_codes(user_id, code_hash, expires_at) "
            "VALUES (?, ?, datetime('now', ?))",
            # Знак форматируем через :+d — иначе отрицательный TTL дал бы
            # "+-10 seconds", а это недопустимый модификатор: datetime() вернёт
            # NULL и упадёт NOT NULL.
            (user_id, code_hash, f"{int(ttl_seconds):+d} seconds"),
        )
        return cur.lastrowid


def consume_enroll_code(code_hash: str) -> sqlite3.Row | None:
    """Атомарно гасит код и возвращает его строку.

    Пометка used_at и проверка «не использован / не истёк» идут ОДНИМ UPDATE:
    иначе два одновременных запроса с одним кодом могли бы оба пройти проверку
    и привязать два устройства.
    """
    with connect() as conn:
        cur = conn.execute(
            "UPDATE enroll_codes SET used_at = datetime('now') "
            "WHERE code_hash = ? AND used_at IS NULL AND expires_at > datetime('now')",
            (code_hash,),
        )
        if cur.rowcount == 0:
            return None
        return conn.execute(
            "SELECT * FROM enroll_codes WHERE code_hash = ?", (code_hash,)
        ).fetchone()


def attach_enroll_device(code_hash: str, device_id: int) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE enroll_codes SET device_id = ? WHERE code_hash = ?",
            (device_id, code_hash),
        )


def purge_expired_enroll_codes() -> None:
    """Чистим отработавшее — таблица не должна расти бесконечно."""
    with connect() as conn:
        conn.execute(
            "DELETE FROM enroll_codes "
            "WHERE expires_at < datetime('now', '-1 day') OR used_at < datetime('now', '-1 day')"
        )


def revoke_device(device_id: int) -> int:
    """Отозвать устройство и снять его конфиги (credentials.toml пересоберётся)."""
    with connect() as conn:
        conn.execute(
            "UPDATE app_devices SET revoked_at = datetime('now') "
            "WHERE id = ? AND revoked_at IS NULL",
            (device_id,),
        )
        cur = conn.execute(
            "UPDATE configs SET revoked_at = datetime('now') "
            "WHERE device_id = ? AND revoked_at IS NULL",
            (device_id,),
        )
        return cur.rowcount


def create_email_token(token: str, user_id: int, purpose: str, expires_at: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO email_tokens(token, user_id, purpose, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, purpose, expires_at),
        )


def get_email_token(token: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM email_tokens WHERE token = ?", (token,)).fetchone()


def delete_email_token(token: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM email_tokens WHERE token = ?", (token,))


def counts() -> dict[str, int]:
    with connect() as conn:
        users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        blocked = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE status = 'blocked'"
        ).fetchone()["c"]
        cfgs = conn.execute(
            "SELECT COUNT(*) AS c FROM configs WHERE revoked_at IS NULL"
        ).fetchone()["c"]
    return {"users": users, "blocked": blocked, "configs": cfgs}

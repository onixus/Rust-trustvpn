"""Конфигурация из окружения. Всё опционально — есть разумные дефолты."""
import os
import secrets
from pathlib import Path

# Каталог с данными (SQLite, сгенерированные конфиги endpoint'а).
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
RUNTIME_DIR = Path(os.environ.get("RUNTIME_DIR", str(DATA_DIR / "runtime")))
DB_PATH = os.environ.get("DB_PATH", str(DATA_DIR / "trusttunnel-web.db"))

# Bootstrap-администратор (создаётся при первом старте, если админов нет).
BOOTSTRAP_ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin12345")

# Каталог с сертификатами Let's Encrypt (режим external — панель за прокси).
# Внутри ожидаются подкаталоги live/<domain>/{fullchain.pem,privkey.pem}.
CERT_DIR = os.environ.get("CERT_DIR", "/etc/letsencrypt")

# Бинарь VPN-endpoint'а и его рабочая директория внутри контейнера.
ENDPOINT_BIN = os.environ.get("ENDPOINT_BIN", "/opt/trusttunnel/trusttunnel_endpoint")
ENDPOINT_WORKDIR = os.environ.get("ENDPOINT_WORKDIR", "/opt/trusttunnel")

# Публичный адрес сервера по умолчанию (что показываем клиенту как address),
# если админ не задал его в настройках.
PUBLIC_ADDRESS = os.environ.get("PUBLIC_ADDRESS", "")

ACCESS_TOKEN_TTL_MIN = int(os.environ.get("ACCESS_TOKEN_TTL_MIN", "43200"))  # 30 дней


def _load_or_create_secret() -> str:
    """Персистентный SECRET_KEY: из env, иначе из файла в DATA_DIR (генерим один раз)."""
    if env := os.environ.get("SECRET_KEY"):
        return env
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secret_file = DATA_DIR / ".secret_key"
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(48)
    secret_file.write_text(value, encoding="utf-8")
    return value


SECRET_KEY = _load_or_create_secret()

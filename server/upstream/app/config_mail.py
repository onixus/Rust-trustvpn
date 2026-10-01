"""Administrator-triggered delivery to the profile owner's stored email."""
import hashlib
import hmac
import logging
import threading
import time
from email.headerregistry import Address
from . import config, db, conninfo, mailer
from .client_config import build_client_toml

_lock = threading.Lock()
_last = {}

class MailError(Exception):
    pass

def token(session, user_id):
    return hmac.new(config.SECRET_KEY.encode(), f'config-mail:{user_id}:{session}'.encode(), hashlib.sha256).hexdigest()

def valid_token(session, user_id, supplied):
    return bool(session) and hmac.compare_digest(token(session, user_id), supplied)

def send(user_id, config_id=0):
    user = db.get_user(user_id)
    if not user or user['status'] != 'active':
        raise MailError('Пользователь не найден или заблокирован.')
    try:
        email = user['email'].strip()
        addr = Address(addr_spec=email)
        if not addr.username or not addr.domain or '\r' in email or '\n' in email:
            raise ValueError()
    except ValueError:
        raise MailError('Проверьте email пользователя.') from None
    if not mailer.is_configured():
        raise MailError('SMTP не настроен.')
    configs = db.list_user_configs(user_id)
    if config_id:
        configs = [c for c in configs if c['id'] == config_id]
    if not configs:
        raise MailError('Нет выбранных конфигов для отправки.')
    with _lock:
        now = time.monotonic()
        if now - _last.get(user_id, -1000) < 60:
            raise MailError('Повторная отправка доступна через минуту.')
        _last[user_id] = now
    try:
        settings = db.get_settings()
        lines = ['Ваши профили TrustTunnel.', 'Импортируйте ссылку в приложение TrustTunnel или используйте приложенный TOML в официальном клиенте.', 'Профили содержат данные доступа. Не передавайте их другим людям.', '']
        attachments = []
        for cfg in configs:
            info = conninfo.connection_info(cfg, settings)
            lines += [str(info['label']), info['deeplink'], '']
            attachments.append((f'trusttunnel-{cfg["id"]}.toml', build_client_toml(info)))
        mailer.send_mail(email, 'Ваши конфигурации TrustTunnel', '\n'.join(lines), attachments=attachments)
    except Exception as exc:
        with _lock:
            _last.pop(user_id, None)
        logging.getLogger(__name__).warning('Config email failed user_id=%s error_type=%s', user_id, type(exc).__name__)
        raise MailError('Не удалось отправить письмо. Проверьте SMTP и повторите попытку.') from None
    logging.getLogger(__name__).info('Config email accepted user_id=%s count=%s', user_id, len(configs))
    return len(configs)

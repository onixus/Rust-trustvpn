"""Отправка почты по SMTP-настройкам из БД. Используется для писем сброса пароля."""
import smtplib
import ssl
import socket
import os
from email.message import EmailMessage

from . import db


class DNSRelaySMTP(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        raw = socket.create_connection((os.environ.get("SMTP_CONNECT_HOST") or host, port), timeout)
        return self.context.wrap_socket(raw, server_hostname=host)


def is_configured() -> bool:
    return bool(db.get_setting("smtp_host"))


def send_mail(to: str, subject: str, body: str, attachments: list[tuple[str, str]] | None = None) -> None:
    """Синхронная отправка (роут выполняется в threadpool). Бросает при ошибке."""
    host = db.get_setting("smtp_host")
    if not host:
        raise RuntimeError("SMTP не настроен")
    port = int(db.get_setting("smtp_port") or "587")
    tls = (db.get_setting("smtp_tls") or "starttls").lower()
    user = db.get_setting("smtp_user")
    password = db.get_setting("smtp_password")
    sender = db.get_setting("smtp_from") or user

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    for filename, content in attachments or []:
        msg.add_attachment(content.encode("utf-8"), maintype="application", subtype="octet-stream", filename=filename)

    if tls == "ssl":
        server: smtplib.SMTP = DNSRelaySMTP(host, port, timeout=15, context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(host, port, timeout=15)
    try:
        if tls == "starttls":
            server.starttls(context=ssl.create_default_context())
        if user:
            server.login(user, password)
        server.send_message(msg)
    finally:
        server.quit()

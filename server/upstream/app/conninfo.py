"""Сборка параметров подключения, которые видит клиент (и файл на скачивание)."""
import json
import sqlite3

from . import config, endpoint
from .deeplink import build_deeplink


def connection_info(cfg: sqlite3.Row, settings: dict[str, str]) -> dict:
    domain = endpoint.effective_domain(settings)          # домен из сертификата
    address = (settings.get("conn_address") or "").strip() or domain or config.PUBLIC_ADDRESS
    port = settings.get("conn_port", "8443")
    info = {
        "label": cfg["label"] or cfg["tt_username"],
        "address": address,
        "port": port,
        "domain": domain,
        "sni": settings.get("conn_sni", ""),
        "username": cfg["tt_username"],
        "password": cfg["tt_password"],
        "protocol": settings.get("conn_protocol", "QUIC"),
        "deeplink": build_deeplink(cfg["tt_username"], cfg["tt_password"], address or domain, int(port or "8443")),
        # какие поля показывать
        "show_address": settings.get("show_address") == "1",
        "show_port": settings.get("show_port") == "1",
        "show_domain": settings.get("show_domain") == "1",
        "show_sni": settings.get("show_sni") == "1" and bool(settings.get("conn_sni")),
        "show_username": settings.get("show_username") == "1",
        "show_password": settings.get("show_password") == "1",
        "show_protocol": settings.get("show_protocol") == "1",
    }
    return info


def as_download_text(info: dict, brand: str) -> str:
    lines = [
        f"# {brand} — параметры подключения TrustTunnel",
        f"# Конфиг: {info['label']}",
        "",
    ]
    if info["show_address"]:
        lines.append(f"Адрес сервера : {info['address']}")
    if info["show_port"]:
        lines.append(f"Порт          : {info['port']}")
    if info["show_domain"] and info["domain"]:
        lines.append(f"Домен (SNI)   : {info['domain']}")
    if info["show_sni"]:
        lines.append(f"Custom SNI    : {info['sni']}")
    if info["show_protocol"]:
        lines.append(f"Протокол      : {info['protocol']}")
    if info["show_username"]:
        lines.append(f"Логин         : {info['username']}")
    if info["show_password"]:
        lines.append(f"Пароль        : {info['password']}")
    lines += ["", f"# deeplink: {info['deeplink']}", ""]
    return "\n".join(lines)


def as_download_json(info: dict) -> str:
    keys = ["label", "address", "port", "domain", "sni", "protocol", "username", "password", "deeplink"]
    return json.dumps({k: info[k] for k in keys}, ensure_ascii=False, indent=2)

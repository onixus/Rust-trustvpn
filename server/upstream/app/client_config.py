import json
import os
from pathlib import Path
"""Сборка client.toml для официального trusttunnel_client.exe.

Формат — эталонный, сверен на живом setup_wizard v1.0.49 (не «по докам»).
Полный шаблон с дефолтами официального визарда; подставляем только параметры
подключения. Критично: excluded_routes исключают LAN — иначе локальная сеть
пойдёт в туннель.

Маппинг (важно):
  hostname   = домен сертификата (TLS-валидация)   ← conn_domain / effective_domain
  custom_sni = маскировочный SNI, если задан        ← conn_sni
  addresses  = куда коннектиться                     ← conn_address:port
"""


def _q(v: str) -> str:
    return json.dumps(v or "", ensure_ascii=False)


def _upstream_protocol(protocol: str) -> str:
    p = (protocol or "").strip().lower()
    return "http3" if p in ("quic", "http3", "http/3", "h3") else "http2"


def build_client_toml(info: dict, killswitch: bool = False) -> str:
    """info = conninfo.connection_info(cfg, settings)."""
    hostname = (info.get("domain") or "").strip() or (info.get("address") or "").strip()
    address = f"{info['address']}:{info['port']}"
    custom_sni = (info.get("sni") or "").strip()
    return _TEMPLATE.format(
        certificate=_q(Path(os.environ["CLIENT_CA_FILE"]).read_text()) if os.environ.get("CLIENT_CA_FILE") else _q(""),
        killswitch="true" if killswitch else "false",
        hostname=_q(hostname),
        addresses=_q(address),
        custom_sni=_q(custom_sni),
        username=_q(info["username"]),
        password=_q(info["password"]),
        upstream=_q(_upstream_protocol(info.get("protocol", "QUIC"))),
    )


# Полный эталонный шаблон (setup_wizard v1.0.49). Значения подставляются, всё
# остальное — дефолты официального визарда.
_TEMPLATE = """# Сгенерировано trusttunnel-web. Не редактировать вручную.
loglevel = "info"
vpn_mode = "general"
killswitch_enabled = {killswitch}
killswitch_allow_ports = []
post_quantum_group_enabled = true
exclusions = []

[endpoint]
hostname = {hostname}
addresses = [{addresses}]
custom_sni = {custom_sni}
has_ipv6 = false
username = {username}
password = {password}
client_random = ""
skip_verification = false
certificate = {certificate}
upstream_protocol = {upstream}
anti_dpi = false
dns_upstreams = []

[listener]

[listener.tun]
bound_if = ""
included_routes = ["0.0.0.0/0", "2000::/3"]
excluded_routes = ["0.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"]
mtu_size = 1280
change_system_dns = true
"""

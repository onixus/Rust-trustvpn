"""trusttunnel-web — минимальная одно-контейнерная панель TrustTunnel.

Одно FastAPI-приложение отдаёт клиентскую часть (`/`) и админку (`/admin`),
и оно же (через endpoint.manager) супервизит VPN-endpoint в том же контейнере.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import db, endpoint
from .config import DATA_DIR


@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db()
    # Свести файлы endpoint'а к текущим настройкам и запустить (если есть домен+серт).
    try:
        endpoint.manager.reconcile()
        endpoint.manager.start_cert_watcher()
    except Exception as e:  # проблема с endpoint не должна ронять панель
        print(f"[startup] endpoint reconcile failed: {e}")
    yield
    endpoint.manager.stop()


app = FastAPI(title="trusttunnel-web", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# Роутеры подключаем после создания app, чтобы избежать циклических импортов.
from .routes_client import router as client_router  # noqa: E402
from .routes_admin import router as admin_router     # noqa: E402
from .routes_device import router as device_router   # noqa: E402

app.include_router(admin_router)   # /admin*
app.include_router(device_router)  # /connect + /portal/v1/device/* (конкретные пути)
app.include_router(client_router)  # /* (регистрируем последним — самый общий префикс)

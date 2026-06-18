"""LeakWatch — FastAPI entrypoint.

Detects whether Docker containers that should be behind a VPN are leaking the
host's real public IP. See README for the full design.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from analyzer import VALID_RULES
from models import Config, SetRuleRequest
from service import LeakWatch
from settings_store import SettingsStore

logging.basicConfig(
    level=os.environ.get("LEAKWATCH_LOG", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("leakwatch")

APP_VERSION = "3.3.0"

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = Config()
    store = SettingsStore()
    try:
        watcher = LeakWatch(config, store)
        state["watcher"] = watcher
        state["config"] = config
        log.info("LeakWatch started. Config: %s", config.as_dict())
    except Exception as e:  # noqa: BLE001
        log.error("Failed to initialise Docker client: %s", e)
        state["watcher"] = None
        state["init_error"] = str(e)
    yield
    w = state.get("watcher")
    if w:
        w.close()
    store.close()


app = FastAPI(title="LeakWatch", version=APP_VERSION, lifespan=lifespan)
api = APIRouter(prefix="/api")


def _watcher() -> LeakWatch:
    w = state.get("watcher")
    if w is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Docker is not reachable. Ensure /var/run/docker.sock is mounted "
                f"into the container. ({state.get('init_error', 'unknown error')})"
            ),
        )
    return w


@api.get("/health")
def health():
    w = state.get("watcher")
    if w is None:
        return JSONResponse(
            status_code=503,
            content={"status": "down", "docker_ok": False, "error": state.get("init_error")},
        )
    return w.health()


@api.get("/config")
def get_config():
    cfg = state.get("config")
    return cfg.as_dict() if cfg else {}


@api.get("/catalog")
def catalog():
    from app_catalog import CATALOG
    return {"apps": [dict(info.as_dict(), keywords=list(kws)) for kws, info in CATALOG]}


@api.get("/host")
def host(refresh: bool = False):
    return _watcher().host_info(refresh=refresh)


@api.get("/containers")
def containers():
    """Current container list with cached results (no live scan)."""
    return _watcher().list_state()


@api.post("/scan")
def scan():
    """Run a full live scan: host + every container."""
    return _watcher().scan_all()


@api.post("/scan/{name}")
def scan_one(name: str):
    result = _watcher().scan_container(name)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Container '{name}' not found.")
    return result


@api.get("/settings")
def get_settings():
    return _watcher().store.get_all_rules()


@api.put("/settings/{name}")
def set_setting(name: str, body: SetRuleRequest):
    if not body.valid():
        raise HTTPException(
            status_code=400,
            detail=f"Invalid rule '{body.rule}'. Must be one of: {sorted(VALID_RULES)}",
        )
    _watcher().set_rule(name, body.rule)
    return {"name": name, "rule": body.rule}


@api.get("/version")
def version():
    return {"version": APP_VERSION}


app.include_router(api)


# Serve the SPA. Registered last so /api/* routes take precedence.
if os.path.isdir(STATIC_DIR):
    @app.get("/")
    def index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    cfg = Config()
    uvicorn.run("main:app", host="0.0.0.0", port=cfg.port, reload=False)

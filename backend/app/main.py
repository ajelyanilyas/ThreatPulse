import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .db import init_db
from .routers import admin, enrich, iocs, stats, watchlist
from .scheduler import run_ingest_job, shutdown_scheduler, start_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("threatpulse")

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db()

    if settings.ingest_on_startup:
        # Run the first pull in a background thread so startup isn't blocked
        # (Render's health check would otherwise time out on a cold DB).
        threading.Thread(target=run_ingest_job, daemon=True).start()

    start_scheduler()
    log.info("ThreatPulse online")
    yield
    shutdown_scheduler()


app = FastAPI(
    title="ThreatPulse",
    description="Live, self-updating threat intelligence platform.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(stats.router)
app.include_router(iocs.router)
app.include_router(enrich.router)
app.include_router(watchlist.router)
app.include_router(admin.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Serve the dashboard SPA at the root. Mounted last so /api/* wins.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

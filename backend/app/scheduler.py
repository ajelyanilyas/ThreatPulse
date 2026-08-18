import logging

from apscheduler.schedulers.background import BackgroundScheduler

from .config import get_settings
from .db import SessionLocal
from .feeds.ingest import ingest_all

log = logging.getLogger("threatpulse.scheduler")
_scheduler: BackgroundScheduler | None = None


def run_ingest_job() -> None:
    """Entrypoint the scheduler calls each interval. Owns its own DB session."""
    db = SessionLocal()
    try:
        runs = ingest_all(db)
        new = sum(r.rows_new for r in runs)
        log.info("scheduled ingest complete: %d new indicators", new)
    finally:
        db.close()


def start_scheduler() -> BackgroundScheduler | None:
    global _scheduler
    settings = get_settings()
    if not settings.scheduler_enabled:
        log.info("scheduler disabled via config")
        return None

    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        run_ingest_job,
        "interval",
        minutes=settings.ingest_interval_minutes,
        id="ingest",
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    log.info("scheduler started: ingest every %d min", settings.ingest_interval_minutes)
    return _scheduler


def shutdown_scheduler() -> None:
    if _scheduler:
        _scheduler.shutdown(wait=False)

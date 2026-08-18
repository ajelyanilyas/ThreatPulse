import threading

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import FeedRun
from ..scheduler import run_ingest_job

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.post("/ingest")
def trigger_ingest():
    """Kick off an ingest run out-of-band (used by the UI button and cron pings)."""
    threading.Thread(target=run_ingest_job, daemon=True).start()
    return {"status": "started"}


@router.get("/feed-runs")
def feed_runs(db: Session = Depends(get_db), limit: int = 20):
    rows = db.scalars(
        select(FeedRun).order_by(FeedRun.started_at.desc()).limit(limit)
    ).all()
    return [
        {
            "source": r.source,
            "status": r.status,
            "rows_new": r.rows_new,
            "rows_updated": r.rows_updated,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
            "error": r.error,
        }
        for r in rows
    ]

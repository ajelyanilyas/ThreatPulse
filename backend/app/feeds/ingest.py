import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import FeedRun, IOC, utcnow
from . import FEEDS
from .base import BaseFeed, RawIOC

log = logging.getLogger("threatpulse.ingest")


def _upsert(db: Session, raw: RawIOC) -> str:
    """Insert a new IOC or bump last_seen on an existing one. Returns 'new'|'updated'."""
    existing = db.scalar(
        select(IOC).where(
            IOC.value == raw.value,
            IOC.ioc_type == raw.ioc_type,
            IOC.source == raw.source,
        )
    )
    now = utcnow()
    if existing:
        existing.last_seen = now
        # Backfill fields that may have been empty on first sighting.
        existing.malware_family = existing.malware_family or raw.malware_family
        existing.country = existing.country or raw.country
        existing.confidence = existing.confidence or raw.confidence
        return "updated"

    db.add(
        IOC(
            value=raw.value,
            ioc_type=raw.ioc_type,
            source=raw.source,
            malware_family=raw.malware_family,
            threat_type=raw.threat_type,
            confidence=raw.confidence,
            country=raw.country,
            tags=",".join(raw.tags) if raw.tags else None,
            reference=raw.reference,
            first_seen=now,
            last_seen=now,
        )
    )
    return "new"


def ingest_feed(db: Session, feed: BaseFeed) -> FeedRun:
    run = FeedRun(source=feed.name)
    db.add(run)
    db.commit()

    try:
        rows = feed.fetch()
        new = updated = 0
        for raw in rows:
            result = _upsert(db, raw)
            new += result == "new"
            updated += result == "updated"
            # Commit in batches so a late failure doesn't lose everything.
            if (new + updated) % 500 == 0:
                db.commit()
        db.commit()

        run.status = "ok"
        run.rows_new = new
        run.rows_updated = updated
        log.info("feed %s: %d new, %d updated", feed.name, new, updated)
    except Exception as exc:  # noqa: BLE001 - one feed must not sink the rest
        db.rollback()
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"
        log.exception("feed %s failed", feed.name)
    finally:
        run.finished_at = utcnow()
        db.commit()

    return run


def ingest_all(db: Session) -> list[FeedRun]:
    """Run every registered feed. Isolated so one failure never blocks others."""
    return [ingest_feed(db, feed) for feed in FEEDS]

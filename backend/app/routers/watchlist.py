from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..enrichment.engine import classify
from ..models import IOC, Watchlist
from ..schemas import WatchlistIn, WatchlistItem

router = APIRouter(prefix="/api/watchlist", tags=["watchlist"])


def _item(db: Session, w: Watchlist) -> WatchlistItem:
    """Attach live sighting history from the IOC table to a watched value."""
    agg = db.execute(
        select(
            func.count(),
            func.min(IOC.first_seen),
            func.max(IOC.last_seen),
        ).where(IOC.value == w.value)
    ).one()
    sources = db.scalars(
        select(func.distinct(IOC.source)).where(IOC.value == w.value)
    ).all()
    return WatchlistItem(
        id=w.id,
        value=w.value,
        ioc_type=w.ioc_type,
        note=w.note,
        created_at=w.created_at,
        sightings=agg[0] or 0,
        first_seen=agg[1],
        last_seen=agg[2],
        sources=list(sources),
    )


@router.get("", response_model=list[WatchlistItem])
def list_watchlist(db: Session = Depends(get_db)):
    rows = db.scalars(select(Watchlist).order_by(Watchlist.created_at.desc())).all()
    return [_item(db, w) for w in rows]


@router.post("", response_model=WatchlistItem, status_code=201)
def add_watch(payload: WatchlistIn, db: Session = Depends(get_db)):
    value = payload.value.strip()
    if not value:
        raise HTTPException(400, "value is required")
    existing = db.scalar(select(Watchlist).where(Watchlist.value == value))
    if existing:
        return _item(db, existing)
    w = Watchlist(value=value, ioc_type=classify(value), note=payload.note)
    db.add(w)
    db.commit()
    db.refresh(w)
    return _item(db, w)


@router.delete("/{watch_id}", status_code=204)
def remove_watch(watch_id: int, db: Session = Depends(get_db)):
    w = db.get(Watchlist, watch_id)
    if not w:
        raise HTTPException(404, "not found")
    db.delete(w)
    db.commit()

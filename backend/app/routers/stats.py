from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import IOC
from ..schemas import (
    MapPoint,
    NamedCount,
    StatCards,
    StatsOut,
    TrendPoint,
)

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    start_today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total = db.scalar(select(func.count()).select_from(IOC)) or 0
    new_today = (
        db.scalar(select(func.count()).select_from(IOC).where(IOC.first_seen >= start_today))
        or 0
    )
    unique_families = (
        db.scalar(
            select(func.count(func.distinct(IOC.malware_family))).where(
                IOC.malware_family.is_not(None)
            )
        )
        or 0
    )
    active_feeds = db.scalar(select(func.count(func.distinct(IOC.source)))) or 0

    top_families = [
        NamedCount(name=name, count=count)
        for name, count in db.execute(
            select(IOC.malware_family, func.count())
            .where(IOC.malware_family.is_not(None))
            .group_by(IOC.malware_family)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    ]
    by_type = [
        NamedCount(name=name, count=count)
        for name, count in db.execute(
            select(IOC.ioc_type, func.count()).group_by(IOC.ioc_type).order_by(func.count().desc())
        ).all()
    ]
    by_source = [
        NamedCount(name=name, count=count)
        for name, count in db.execute(
            select(IOC.source, func.count()).group_by(IOC.source).order_by(func.count().desc())
        ).all()
    ]

    # 14-day trend of first-seen indicators.
    since = start_today - timedelta(days=13)
    day = func.date(IOC.first_seen)
    rows = db.execute(
        select(day, func.count()).where(IOC.first_seen >= since).group_by(day)
    ).all()
    counts = {str(d): c for d, c in rows}
    trend = [
        TrendPoint(
            date=(since + timedelta(days=i)).strftime("%Y-%m-%d"),
            count=counts.get((since + timedelta(days=i)).strftime("%Y-%m-%d"), 0),
        )
        for i in range(14)
    ]

    world = [
        MapPoint(country=country, count=count)
        for country, count in db.execute(
            select(IOC.country, func.count())
            .where(IOC.country.is_not(None))
            .group_by(IOC.country)
            .order_by(func.count().desc())
        ).all()
    ]

    last_updated = db.scalar(select(func.max(IOC.last_seen)))

    return StatsOut(
        cards=StatCards(
            total_iocs=total,
            new_today=new_today,
            active_feeds=active_feeds,
            unique_families=unique_families,
        ),
        top_families=top_families,
        by_type=by_type,
        by_source=by_source,
        trend=trend,
        map=world,
        last_updated=last_updated,
    )

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import IOC
from ..schemas import IOCPage

router = APIRouter(prefix="/api/iocs", tags=["iocs"])

SORT_COLUMNS = {
    "last_seen": IOC.last_seen,
    "first_seen": IOC.first_seen,
    "confidence": IOC.confidence,
}


@router.get("", response_model=IOCPage)
def list_iocs(
    db: Session = Depends(get_db),
    q: str | None = Query(None, description="Substring match on value/family/tags"),
    ioc_type: str | None = None,
    source: str | None = None,
    malware_family: str | None = None,
    sort: str = Query("last_seen"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Searchable, filterable, paginated indicator table."""
    filters = []
    if q:
        like = f"%{q}%"
        filters.append(
            or_(IOC.value.ilike(like), IOC.malware_family.ilike(like), IOC.tags.ilike(like))
        )
    if ioc_type:
        filters.append(IOC.ioc_type == ioc_type)
    if source:
        filters.append(IOC.source == source)
    if malware_family:
        filters.append(IOC.malware_family == malware_family)

    total = db.scalar(select(func.count()).select_from(IOC).where(*filters)) or 0

    col = SORT_COLUMNS.get(sort, IOC.last_seen)
    col = col.asc() if order == "asc" else col.desc()

    items = db.scalars(
        select(IOC).where(*filters).order_by(col).limit(limit).offset(offset)
    ).all()

    return IOCPage(total=total, limit=limit, offset=offset, items=list(items))

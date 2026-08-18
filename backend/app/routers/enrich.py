from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..enrichment.engine import enrich
from ..schemas import EnrichIn

router = APIRouter(prefix="/api/enrich", tags=["enrich"])


@router.post("")
def enrich_indicator(payload: EnrichIn, db: Session = Depends(get_db)):
    """Paste an IOC, get a verdict card back."""
    return enrich(db, payload.indicator).to_dict()

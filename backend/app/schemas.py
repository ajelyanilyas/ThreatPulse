from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    ioc_type: str
    source: str
    malware_family: str | None
    threat_type: str | None
    confidence: int | None
    country: str | None
    tags: str | None
    reference: str | None
    first_seen: datetime
    last_seen: datetime


class IOCPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IOCOut]


class StatCards(BaseModel):
    total_iocs: int
    new_today: int
    active_feeds: int
    unique_families: int


class NamedCount(BaseModel):
    name: str
    count: int


class TrendPoint(BaseModel):
    date: str
    count: int


class MapPoint(BaseModel):
    country: str
    count: int


class StatsOut(BaseModel):
    cards: StatCards
    top_families: list[NamedCount]
    by_type: list[NamedCount]
    by_source: list[NamedCount]
    trend: list[TrendPoint]
    map: list[MapPoint]
    last_updated: datetime | None


class EnrichIn(BaseModel):
    indicator: str


class WatchlistIn(BaseModel):
    value: str
    note: str | None = None


class WatchlistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    ioc_type: str | None
    note: str | None
    created_at: datetime


class WatchlistItem(WatchlistOut):
    sightings: int
    first_seen: datetime | None
    last_seen: datetime | None
    sources: list[str]

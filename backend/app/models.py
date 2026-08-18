from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IOC(Base):
    """A single indicator of compromise ingested from a threat feed.

    Uniqueness is (value, ioc_type, source) so the same indicator seen in two
    feeds is tracked separately, and re-ingesting only bumps last_seen.
    """

    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("value", "ioc_type", "source", name="uq_ioc_value_type_source"),
        Index("ix_ioc_type", "ioc_type"),
        Index("ix_ioc_source", "source"),
        Index("ix_ioc_last_seen", "last_seen"),
        Index("ix_ioc_malware", "malware_family"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    # ip | domain | url | md5 | sha256 | ...
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # urlhaus | threatfox | feodo
    source: Mapped[str] = mapped_column(String(64), nullable=False)

    malware_family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Coarse geolocation for the world map; filled best-effort at ingest time.
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)

    tags: Mapped[str | None] = mapped_column(Text, nullable=True)  # comma-separated
    reference: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class FeedRun(Base):
    """One execution of one feed's ingestion, for observability."""

    __tablename__ = "feed_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), default="running", nullable=False)
    rows_new: Mapped[int] = mapped_column(Integer, default=0)
    rows_updated: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Watchlist(Base):
    """A user-tracked indicator. Sightings accrue against it over time."""

    __tablename__ = "watchlist"
    __table_args__ = (
        UniqueConstraint("value", name="uq_watchlist_value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    ioc_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

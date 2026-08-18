from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


def _normalize_url(url: str) -> str:
    # Render/Heroku hand out postgres:// URLs; SQLAlchemy + psycopg wants
    # postgresql+psycopg://. Normalize so the same env var works everywhere.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


settings = get_settings()
_db_url = _normalize_url(settings.database_url)

# check_same_thread only applies to SQLite; the scheduler thread shares the engine.
_connect_args = {"check_same_thread": False} if _db_url.startswith("sqlite") else {}

engine = create_engine(_db_url, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)

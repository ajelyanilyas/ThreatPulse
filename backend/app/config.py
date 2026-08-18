from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration, sourced from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # SQLite locally; Render injects a Postgres DATABASE_URL in production.
    database_url: str = "sqlite:///./threatpulse.db"

    # How often the background scheduler pulls fresh feeds, in minutes.
    ingest_interval_minutes: int = 60

    # Run an ingest immediately on startup so a fresh deploy has data.
    ingest_on_startup: bool = True

    # Turn the in-process scheduler off (e.g. when a separate cron drives ingest).
    scheduler_enabled: bool = True

    # Cap rows pulled per feed per run to keep the free tier happy.
    max_rows_per_feed: int = 5000

    # Optional abuse.ch Auth-Key. Their APIs accept anonymous access with
    # tighter limits; a free key (auth.abuse.ch) raises them. Feeds work without it.
    abusech_auth_key: str | None = None

    # Optional API keys for the on-demand enrichment tab. All optional —
    # enrichment degrades gracefully to local heuristics when absent.
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None

    http_timeout_seconds: float = 30.0


@lru_cache
def get_settings() -> Settings:
    return Settings()

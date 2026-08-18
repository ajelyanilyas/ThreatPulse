from dataclasses import dataclass, field

import httpx

from ..config import get_settings


@dataclass
class RawIOC:
    """A normalized indicator produced by a feed parser, pre-persistence."""

    value: str
    ioc_type: str
    source: str
    malware_family: str | None = None
    threat_type: str | None = None
    confidence: int | None = None
    country: str | None = None
    tags: list[str] = field(default_factory=list)
    reference: str | None = None


class BaseFeed:
    """Contract every feed implements.

    name    - stable identifier stored on each IOC as `source`.
    fetch() - hit the upstream API/CSV and yield RawIOC objects.
    """

    name: str = "base"

    def fetch(self) -> list[RawIOC]:  # pragma: no cover - interface
        raise NotImplementedError

    def _client(self) -> httpx.Client:
        settings = get_settings()
        headers = {"User-Agent": "ThreatPulse/1.0 (+https://github.com/)"}
        # abuse.ch endpoints accept an optional Auth-Key for higher rate limits.
        if settings.abusech_auth_key:
            headers["Auth-Key"] = settings.abusech_auth_key
        return httpx.Client(
            timeout=settings.http_timeout_seconds,
            headers=headers,
            follow_redirects=True,
        )

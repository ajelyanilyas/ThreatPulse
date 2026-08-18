"""On-demand enrichment: classify an indicator and render a verdict.

Signal sources, in order of weight:
  1. Our own feed database (has abuse.ch seen this exact IOC?).
  2. AbuseIPDB (IP reputation) — optional, key-gated.
  3. AlienVault OTX (pulse count) — optional, key-gated.
Everything degrades gracefully: with no keys, the local DB + heuristics
still produce a defensible verdict.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import IOC

_HASH_RE = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


def classify(indicator: str) -> str:
    """Best-effort type detection for a raw user-supplied string."""
    s = indicator.strip()
    if s.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    for kind, rx in _HASH_RE.items():
        if rx.match(s):
            return kind
    if _DOMAIN_RE.match(s):
        return "domain"
    return "unknown"


@dataclass
class Verdict:
    indicator: str
    ioc_type: str
    score: int = 0            # 0 (clean) .. 100 (malicious)
    verdict: str = "unknown"  # clean | suspicious | malicious | unknown
    sources: list[dict] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return self.__dict__


def _label(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 35:
        return "suspicious"
    return "clean"


def enrich(db: Session, indicator: str) -> Verdict:
    settings = get_settings()
    ioc_type = classify(indicator)
    v = Verdict(indicator=indicator, ioc_type=ioc_type)

    # 1) Local intel: exact matches across our ingested feeds.
    hits = list(
        db.scalars(select(IOC).where(IOC.value == indicator.strip())).all()
    )
    if hits:
        earliest = min(h.first_seen for h in hits)
        latest = max(h.last_seen for h in hits)
        v.first_seen = earliest.isoformat()
        v.last_seen = latest.isoformat()
        families = sorted({h.malware_family for h in hits if h.malware_family})
        feeds = sorted({h.source for h in hits})
        v.score = max(v.score, 90)
        v.sources.append(
            {
                "name": "ThreatPulse feeds",
                "hit": True,
                "detail": f"Listed by {', '.join(feeds)}"
                + (f"; family: {', '.join(families)}" if families else ""),
            }
        )

    # 2) AbuseIPDB for IPs (optional).
    if ioc_type == "ip" and settings.abuseipdb_api_key:
        _abuseipdb(v, indicator, settings.abuseipdb_api_key, settings.http_timeout_seconds)

    # 3) OTX pulse count (optional, any type).
    if settings.otx_api_key:
        _otx(v, indicator, ioc_type, settings.otx_api_key, settings.http_timeout_seconds)

    if not v.sources:
        v.sources.append(
            {"name": "ThreatPulse feeds", "hit": False, "detail": "No match in ingested feeds."}
        )
        v.verdict = "unknown" if ioc_type == "unknown" else "clean"
    else:
        v.verdict = _label(v.score)
    return v


def _abuseipdb(v: Verdict, ip: str, key: str, timeout: float) -> None:
    try:
        with httpx.Client(timeout=timeout) as c:
            r = c.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
            r.raise_for_status()
            data = r.json().get("data", {})
        conf = int(data.get("abuseConfidenceScore", 0))
        v.score = max(v.score, conf)
        v.sources.append(
            {
                "name": "AbuseIPDB",
                "hit": conf > 0,
                "detail": f"Confidence {conf}%, {data.get('totalReports', 0)} reports"
                + (f", {data.get('countryCode')}" if data.get("countryCode") else ""),
            }
        )
    except Exception as exc:  # noqa: BLE001
        v.sources.append({"name": "AbuseIPDB", "hit": False, "detail": f"lookup failed: {exc}"})


def _otx(v: Verdict, indicator: str, ioc_type: str, key: str, timeout: float) -> None:
    section = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
    }.get(ioc_type)
    if not section:
        return
    try:
        with httpx.Client(timeout=timeout) as c:
            r = c.get(
                f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general",
                headers={"X-OTX-API-KEY": key},
            )
            r.raise_for_status()
            data = r.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        if pulses:
            v.score = max(v.score, min(50 + pulses * 5, 95))
        v.sources.append(
            {"name": "AlienVault OTX", "hit": pulses > 0, "detail": f"{pulses} threat pulses"}
        )
    except Exception as exc:  # noqa: BLE001
        v.sources.append({"name": "AlienVault OTX", "hit": False, "detail": f"lookup failed: {exc}"})

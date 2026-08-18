from ..config import get_settings
from .base import BaseFeed, RawIOC

API = "https://threatfox-api.abuse.ch/api/v1/"

# ThreatFox ioc_type -> our normalized type.
TYPE_MAP = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha256_hash": "sha256",
    "sha1_hash": "sha1",
}


class ThreatFoxFeed(BaseFeed):
    """Fresh IOCs (IPs, domains, URLs, hashes) from abuse.ch ThreatFox."""

    name = "threatfox"

    def fetch(self) -> list[RawIOC]:
        settings = get_settings()
        with self._client() as client:
            resp = client.post(API, json={"query": "get_iocs", "days": 1})
            resp.raise_for_status()
            payload = resp.json()

        if payload.get("query_status") != "ok":
            return []

        out: list[RawIOC] = []
        for item in payload.get("data", []):
            raw_type = item.get("ioc_type", "")
            ioc_type = TYPE_MAP.get(raw_type, raw_type or "unknown")
            value = (item.get("ioc") or "").strip()
            if not value:
                continue
            # Normalize "1.2.3.4:443" -> "1.2.3.4" for ip type.
            if ioc_type == "ip" and ":" in value:
                value = value.split(":", 1)[0]

            conf = item.get("confidence_level")
            out.append(
                RawIOC(
                    value=value,
                    ioc_type=ioc_type,
                    source=self.name,
                    malware_family=item.get("malware_printable") or None,
                    threat_type=item.get("threat_type") or None,
                    confidence=int(conf) if isinstance(conf, (int, float)) else None,
                    tags=item.get("tags") or [],
                    reference=item.get("reference") or None,
                )
            )
            if len(out) >= settings.max_rows_per_feed:
                break
        return out

from ..config import get_settings
from .base import BaseFeed, RawIOC

# Botnet C2 IP blocklist (Emotet, Dridex, TrickBot, QakBot, ...), JSON.
BLOCKLIST = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoFeed(BaseFeed):
    """Active botnet command-and-control IPs from abuse.ch Feodo Tracker."""

    name = "feodo"

    def fetch(self) -> list[RawIOC]:
        settings = get_settings()
        with self._client() as client:
            resp = client.get(BLOCKLIST)
            resp.raise_for_status()
            data = resp.json()

        out: list[RawIOC] = []
        for item in data:
            ip = (item.get("ip_address") or "").strip()
            if not ip:
                continue
            tags = []
            if item.get("as_name"):
                tags.append(item["as_name"])
            out.append(
                RawIOC(
                    value=ip,
                    ioc_type="ip",
                    source=self.name,
                    malware_family=item.get("malware") or None,
                    threat_type="botnet_cc",
                    country=(item.get("country") or None),
                    tags=tags,
                    reference="https://feodotracker.abuse.ch/browse/",
                )
            )
            if len(out) >= settings.max_rows_per_feed:
                break
        return out

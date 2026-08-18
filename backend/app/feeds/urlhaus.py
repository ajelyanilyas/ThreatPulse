import csv
import io
import re
from urllib.parse import urlparse

from ..config import get_settings
from .base import BaseFeed, RawIOC

# Recent-URLs CSV dump (last ~30 days of additions). Public, comment-prefixed.
RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"


class URLhausFeed(BaseFeed):
    """Malicious URLs distributing malware, from abuse.ch URLhaus."""

    name = "urlhaus"

    def fetch(self) -> list[RawIOC]:
        settings = get_settings()
        with self._client() as client:
            resp = client.get(RECENT_CSV)
            resp.raise_for_status()
            text = resp.text

        # Strip the leading '#'-comment banner; the last comment line is the header.
        header = [
            "id", "dateadded", "url", "url_status", "last_online",
            "threat", "tags", "urlhaus_link", "reporter",
        ]
        data_lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]

        out: list[RawIOC] = []
        reader = csv.reader(io.StringIO("\n".join(data_lines)))
        for row in reader:
            if len(row) < len(header):
                continue
            rec = dict(zip(header, row))
            url = rec["url"].strip('"').strip()
            if not url:
                continue
            host = urlparse(url).hostname or ""
            tags = [t for t in rec.get("tags", "").strip('"').split(",") if t]
            out.append(
                RawIOC(
                    value=url,
                    ioc_type="url",
                    source=self.name,
                    threat_type=rec.get("threat", "").strip('"') or None,
                    malware_family=_family_from_tags(tags),
                    tags=tags,
                    reference=rec.get("urlhaus_link", "").strip('"') or None,
                )
            )
            if len(out) >= settings.max_rows_per_feed:
                break
        return out


# URLhaus tags mix real malware families with a lot of non-family noise:
# CPU architectures, file formats, downloaders, and scanner/monitoring labels.
# We denylist that noise and treat the first surviving tag as the family.
_NON_FAMILY = {
    # architectures
    "mips", "mipsel", "arm", "arm7", "armv7", "x86", "x86-64", "x64", "i686",
    "sh4", "ppc", "powerpc", "m68k", "sparc", "32-bit", "64-bit",
    # formats / loaders
    "elf", "exe", "dll", "js", "jar", "doc", "docm", "xls", "xlsm", "zip",
    "rar", "7z", "apk", "ps1", "vbs", "hta", "lnk", "iso", "img", "bin",
    "wget", "ua-wget", "ua-curl", "curl", "download", "payload",
    # shells / interpreters / protocols
    "sh", "bash", "python", "perl", "php", "tftp", "ftp", "http", "https", "ssh",
    # scanners / monitoring / meta
    "censys", "c2-monitor-auto", "botnetdomain", "opendir", "none", "unknown",
    "ascii", "geofenced", "test", "malware", "malware-download",
}
_IP_LIKE = re.compile(r"^\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}$")
# 2-3 char all-caps tokens are almost always ISO country/language codes, not families.
_CODE_LIKE = re.compile(r"^[A-Z]{2,3}$")
# host-with-port style labels (e.g. "newstan-online-8443") are not family names.
_HOSTPORT_LIKE = re.compile(r"-\d{2,5}$")


def _family_from_tags(tags: list[str]) -> str | None:
    for t in tags:
        raw = t.strip()
        tl = raw.lower()
        if (
            not tl
            or tl in _NON_FAMILY
            or _IP_LIKE.match(tl)
            or _CODE_LIKE.match(raw)
            or _HOSTPORT_LIKE.search(raw)
        ):
            continue
        return raw
    return None

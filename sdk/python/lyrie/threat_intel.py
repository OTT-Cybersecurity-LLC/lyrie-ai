"""
Lyrie Threat-Intel Client — Python port.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Pulls KEV-aligned advisories from research.lyrie.ai and attributes them
to dependencies + findings. Network-optional: feed unreachable returns
no matches and never raises.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Final, Iterable, Optional

THREAT_INTEL_VERSION: Final[str] = "lyrie-threat-intel-py-1.0.0"
DEFAULT_FEED_URL: Final[str] = "https://research.lyrie.ai/api/feed.json"
SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"


@dataclass(slots=True)
class KevAttribution:
    in_kev: bool = False
    date_added: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[str] = None


@dataclass(slots=True)
class ThreatAdvisory:
    cve: str
    title: str
    severity: str = "medium"
    cvss: Optional[float] = None
    product: Optional[str] = None
    affected_range: Optional[str] = None
    patched_version: Optional[str] = None
    kev: KevAttribution = field(default_factory=KevAttribution)
    summary: str = ""
    verdict: Optional[str] = None
    url: str = ""
    updated_at: str = ""
    slug: Optional[str] = None


def version_affected(version: str, vrange: str) -> bool:
    """Lyrie's lightweight semver-ish range matcher."""
    v = _parse_v(version)
    trimmed = vrange.strip()
    if not trimmed or trimmed == "*":
        return True
    if re.search(r"\s+-\s+", trimmed):
        lo, hi = re.split(r"\s+-\s+", trimmed, maxsplit=1)
        return _cmp(v, _parse_v(lo)) >= 0 and _cmp(v, _parse_v(hi)) <= 0
    m = re.match(r"^(<=|>=|<|>|=|\^|~)?\s*([0-9].*)$", trimmed)
    if not m:
        return False
    op = m.group(1) or "="
    target = _parse_v(m.group(2))
    c = _cmp(v, target)
    return {
        "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0,
        "^": c >= 0 and v[0] == target[0],
        "~": c >= 0 and v[0] == target[0] and v[1] == target[1],
    }.get(op, False)


def _parse_v(s: str) -> tuple[int, int, int]:
    parts = re.split(r"[.+\-]", s.lstrip("vV"))[:3]
    nums: list[int] = []
    for p in parts:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def _cmp(a: tuple[int, int, int], b: tuple[int, int, int]) -> int:
    for ai, bi in zip(a, b):
        if ai != bi:
            return ai - bi
    return 0


def _normalize(raw: object) -> Optional[ThreatAdvisory]:
    if not isinstance(raw, dict):
        return None
    cve = str(raw.get("cve") or "")
    title = str(raw.get("title") or "")
    if not cve or not title:
        return None
    sev = str(raw.get("severity") or "medium")
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    kev_raw = raw.get("kev") or {}
    return ThreatAdvisory(
        cve=cve,
        title=title,
        severity=sev,
        cvss=float(raw["cvss"]) if isinstance(raw.get("cvss"), (int, float)) else None,
        product=raw.get("product") if isinstance(raw.get("product"), str) else None,
        affected_range=raw.get("affectedRange") if isinstance(raw.get("affectedRange"), str) else None,
        patched_version=raw.get("patchedVersion") if isinstance(raw.get("patchedVersion"), str) else None,
        kev=KevAttribution(
            in_kev=bool(kev_raw.get("inKev")),
            date_added=kev_raw.get("dateAdded") if isinstance(kev_raw.get("dateAdded"), str) else None,
            required_action=kev_raw.get("requiredAction") if isinstance(kev_raw.get("requiredAction"), str) else None,
            due_date=kev_raw.get("dueDate") if isinstance(kev_raw.get("dueDate"), str) else None,
        ),
        summary=str(raw.get("summary") or ""),
        verdict=raw.get("verdict") if isinstance(raw.get("verdict"), str) else None,
        url=str(raw.get("url") or f"https://research.lyrie.ai/cves/{cve}"),
        updated_at=str(raw.get("updatedAt") or ""),
        slug=raw.get("slug") if isinstance(raw.get("slug"), str) else None,
    )


class ThreatIntelClient:
    """Lyrie Threat-Intel client. Lyrie.ai by OTT Cybersecurity LLC."""

    __slots__ = ("_url", "_offline", "_ttl", "_cache", "_cache_at", "_max_cache")

    def __init__(
        self,
        *,
        feed_url: str = DEFAULT_FEED_URL,
        offline: bool = False,
        cache_ttl_sec: float = 3600,
        max_cache_entries: int = 10_000,
    ) -> None:
        self._url = feed_url
        self._offline = offline
        self._ttl = cache_ttl_sec
        self._cache: list[ThreatAdvisory] = []
        self._cache_at: float = 0.0
        self._max_cache = max_cache_entries

    def refresh(self, *, timeout: float = 10.0) -> list[ThreatAdvisory]:
        if self._offline:
            self._cache, self._cache_at = [], time.time()
            return []
        try:
            req = urllib.request.Request(self._url, headers={
                "Accept": "application/json",
                "User-Agent": f"LyrieAgent/{THREAT_INTEL_VERSION} (+https://lyrie.ai)",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    self._cache, self._cache_at = [], time.time()
                    return []
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            self._cache, self._cache_at = [], time.time()
            return []

        ads_in = payload.get("advisories") if isinstance(payload, dict) else None
        ads: list[ThreatAdvisory] = []
        if isinstance(ads_in, list):
            for item in ads_in[: self._max_cache]:
                norm = _normalize(item)
                if norm:
                    ads.append(norm)
        self._cache, self._cache_at = ads, time.time()
        return ads

    def get_advisories(self) -> list[ThreatAdvisory]:
        if not self._cache or (time.time() - self._cache_at) > self._ttl:
            self.refresh()
        return list(self._cache)

    def seed(self, advisories: Iterable[ThreatAdvisory]) -> None:
        self._cache = list(advisories)
        self._cache_at = time.time()

    def match_findings(
        self,
        findings: Iterable[object],
    ) -> list[tuple[ThreatAdvisory, str]]:
        """Return (advisory, finding_id) tuples for every match."""
        out: list[tuple[ThreatAdvisory, str]] = []
        ads = self.get_advisories()
        if not ads:
            return out
        for f in findings:
            fid = str(getattr(f, "id", ""))
            text = " ".join(
                str(getattr(f, k, "") or "")
                for k in ("title", "description")
            )
            for ad in ads:
                if ad.cve in text:
                    out.append((ad, fid))
                    continue
                if ad.slug and ad.slug.lower() in text.lower():
                    out.append((ad, fid))
        return out

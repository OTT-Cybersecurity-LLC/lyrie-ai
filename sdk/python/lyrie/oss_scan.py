"""
Lyrie OSS-Scan service — Python port.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

The same engine that powers research.lyrie.ai/scan: clone a public repo,
build attack surface, run multi-language scanners, validate through
Stages A–F, return confirmed findings.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Optional

from lyrie.attack_surface import AttackSurfaceMapper
from lyrie.scanners import scan_files
from lyrie.shield import Shield
from lyrie.stages import StagesValidator, ValidatedFinding

OSS_SCAN_VERSION: Final[str] = "lyrie-oss-scan-py-1.0.0"
SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"
DEFAULT_ALLOWED_HOSTS: Final[tuple[str, ...]] = (
    "github.com", "gitlab.com", "bitbucket.org", "codeberg.org",
)


@dataclass(slots=True)
class OssScanResult:
    request_url: str
    resolved_url: str
    started_at: str
    finished_at: str
    files_scanned: int
    entry_points: int
    trust_boundaries: int
    data_flows: int
    dependencies: int
    findings: list[ValidatedFinding]
    languages: list[tuple[str, int]] = field(default_factory=list)
    signature: str = SIGNATURE
    service_version: str = OSS_SCAN_VERSION


@dataclass(slots=True)
class OssScanError:
    ok: bool = False
    reason: str = ""
    detail: Optional[str] = None
    signature: str = SIGNATURE


def _validate_url(url: str, allowed: tuple[str, ...]) -> tuple[bool, str]:
    if not url or len(url) > 1024 or " " in url or "\n" in url:
        return False, "URL is empty, too long, or contains whitespace"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http(s) URLs accepted"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "URL missing host"
    blocked_hosts = ("localhost", "::1")
    if host in blocked_hosts or any(host.startswith(p) for p in (
        "127.", "10.", "192.168.", "169.254.",
    )) or host.endswith(".localhost"):
        return False, "Private / loopback hosts are refused"
    import re
    if re.match(r"^172\.(1[6-9]|2\d|3[01])\.", host):
        return False, "Private / loopback hosts are refused"
    if host not in allowed:
        return False, f"Host {host} not in Lyrie OSS-Scan allowlist"
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        return False, "URL must include /owner/repo"
    if not all(re.match(r"^[A-Za-z0-9._\-]{1,100}$", p) for p in parts[:2]):
        return False, "owner / repo segment is unsafe"
    return True, f"{parsed.scheme}://{host}/{parts[0]}/{parts[1].removesuffix('.git')}.git"


def run_oss_scan(
    repo_url: str,
    *,
    ref: Optional[str] = None,
    allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS,
    total_timeout_sec: float = 120,
    shield: Optional[Shield] = None,
) -> OssScanResult | OssScanError:
    started = datetime.now(tz=timezone.utc).isoformat()
    guard = shield or Shield()

    verdict = guard.scan_inbound(repo_url)
    if verdict.blocked:
        return OssScanError(reason="shield-refused-url", detail=verdict.reason)

    ok, value = _validate_url(repo_url, allowed_hosts)
    if not ok:
        return OssScanError(reason="invalid-repo-url", detail=value)

    canonical = value
    import re as _re
    if ref and not _re.match(r"^[A-Za-z0-9._/\-]{1,128}$", ref):
        return OssScanError(reason="invalid-ref", detail="ref must match [A-Za-z0-9._/-]{1,128}")

    workdir = Path(tempfile.mkdtemp(prefix="lyrie-oss-"))
    try:
        cmd = ["git", "clone", "--depth", "1"]
        if ref:
            cmd += ["--branch", ref]
        cmd += [canonical, str(workdir)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=total_timeout_sec)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            return OssScanError(reason="clone-failed", detail=str(e))

        surface = AttackSurfaceMapper(root=workdir, shield=guard).run()
        ml = scan_files(root=workdir)
        validator = StagesValidator(shield=guard, fast_mode=False)
        validated = validator.validate_batch(ml.findings, surface=surface)

        return OssScanResult(
            request_url=repo_url,
            resolved_url=canonical,
            started_at=started,
            finished_at=datetime.now(tz=timezone.utc).isoformat(),
            files_scanned=ml.scanned_files,
            entry_points=len(surface.entry_points),
            trust_boundaries=len(surface.trust_boundaries),
            data_flows=len(surface.data_flows),
            dependencies=len(surface.dependencies),
            findings=validated,
            languages=ml.languages,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

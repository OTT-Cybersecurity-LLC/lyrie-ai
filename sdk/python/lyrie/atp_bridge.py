"""
`lyrie.atp_bridge` — Python surface for verifying ATP (Agent Trust Protocol)
artifacts.

ATP's cryptographic primitives (Ed25519 signing/verification over canonical
JSON, the AIC/Receipt/Scope/TrustChain/Attestation state machines) are
implemented once, in TypeScript, in `@lyrie/atp` (`packages/atp/src/`). That
package has 160+ passing tests and is the reference implementation the ATP
RFC describes.

Design decision (documented per the build brief): rather than reimplementing
Ed25519 signature verification and ATP's canonical-JSON + expiry/revocation/
scope-subset logic natively in Python — which would create a second,
independently-maintained copy of security-critical crypto logic that could
silently drift from the TypeScript reference implementation — this module
shells out to the existing `lyrie-atp` CLI (`packages/atp/src/cli.ts`) as a
subprocess, passing a JSON file path and reading back JSON on stdout.

This mirrors the established bridge pattern already used elsewhere in this
repo for cross-language reuse: `packages/shield/src/bridge.rs` (Rust Shield
detector invoked via subprocess by TS callers, e.g.
`packages/core/src/engine/agentic-threat-bridge.ts`). Subprocess-JSON is the
lower-risk, more-conservative choice here: no new Python dependency (the SDK
currently has zero runtime `dependencies` in `pyproject.toml`), no drift risk
between two independent crypto implementations, and it works fully offline —
no server, no network call, just a local subprocess.

Requires `bun` on PATH (the same toolchain `@lyrie/atp` itself is built and
tested with — `bun.sh`). If `bun` is not available, `verify_file()` /
`get_status()` raise `AtpBridgeUnavailable` with a clear message rather than
silently failing or producing a wrong verdict.

© OTT Cybersecurity LLC — https://lyrie.ai — MIT License
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

# Resolve packages/atp/src/cli.ts relative to this file:
#   sdk/python/lyrie/atp_bridge.py -> repo root -> packages/atp/src/cli.ts
_REPO_ROOT = Path(__file__).resolve().parents[3]
_CLI_PATH = _REPO_ROOT / "packages" / "atp" / "src" / "cli.ts"

ArtifactKind = Literal["aic", "receipt", "scope", "trust-chain", "attestation"]


class AtpBridgeUnavailable(RuntimeError):
    """Raised when the `bun`/`lyrie-atp` bridge cannot be invoked."""


class AtpBridgeError(RuntimeError):
    """Raised when the bridge subprocess fails unexpectedly (non-usage-error)."""


@dataclass
class AtpVerifyResult:
    """Mirrors the TypeScript `VerificationResult` shape."""

    kind: ArtifactKind | None
    valid: bool
    code: str | None = None
    reason: str | None = None
    details: list[dict[str, Any]] | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "AtpVerifyResult":
        return cls(
            kind=data.get("kind"),
            valid=bool(data.get("valid", False)),
            code=data.get("code"),
            reason=data.get("reason"),
            details=data.get("details"),
        )


def _bun_path() -> str:
    bun = shutil.which("bun")
    if not bun:
        raise AtpBridgeUnavailable(
            "lyrie-atp bridge requires `bun` on PATH (https://bun.sh) — "
            "ATP verification primitives are implemented in @lyrie/atp (TypeScript); "
            "this Python SDK shells out to them rather than reimplementing "
            "Ed25519/canonical-JSON crypto natively. Install bun or run "
            "`bun run packages/atp/src/cli.ts` directly."
        )
    return bun


def _run_cli(command: Literal["verify", "status"], file_path: str) -> AtpVerifyResult:
    bun = _bun_path()
    if not _CLI_PATH.exists():
        raise AtpBridgeUnavailable(f"lyrie-atp CLI not found at expected path: {_CLI_PATH}")

    try:
        proc = subprocess.run(
            [bun, "run", str(_CLI_PATH), command, file_path, "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise AtpBridgeError(f"lyrie-atp bridge timed out: {exc}") from exc
    except OSError as exc:
        raise AtpBridgeError(f"failed to invoke lyrie-atp bridge: {exc}") from exc

    stdout = proc.stdout.strip()
    if not stdout:
        raise AtpBridgeError(
            f"lyrie-atp bridge produced no output (exit code {proc.returncode}): {proc.stderr.strip()}"
        )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AtpBridgeError(
            f"lyrie-atp bridge returned non-JSON output: {stdout!r} (stderr: {proc.stderr.strip()})"
        ) from exc

    return AtpVerifyResult.from_json(data)


def verify_file(path: str) -> AtpVerifyResult:
    """
    Verify an ATP artifact JSON file. Returns an `AtpVerifyResult` whose
    `.valid` reflects whether the artifact passed verification.

    File shapes (same as the TS CLI):
      - aic / scope / trust-chain: bare artifact JSON.
      - receipt / attestation: {"artifact": <receipt-or-attestation>, "cert": <AIC>}.

    Raises `AtpBridgeUnavailable` if `bun` isn't installed, or
    `AtpBridgeError` if the subprocess fails unexpectedly (crash, bad JSON).
    A malformed/unrecognized *artifact* (as opposed to a bridge failure)
    is NOT an exception — it's a normal `AtpVerifyResult(valid=False, code="ATP_MALFORMED", ...)`.
    """
    return _run_cli("verify", path)


def get_status(path: str) -> AtpVerifyResult:
    """
    Like `verify_file()`, but mirrors the CLI's `status` subcommand: always
    completes without raising for invalid-but-parseable artifacts (still
    raises `AtpBridgeUnavailable`/`AtpBridgeError` for bridge-level failures).
    """
    return _run_cli("status", path)


def is_available() -> bool:
    """True if the bridge (bun + the lyrie-atp CLI file) can be invoked."""
    try:
        _bun_path()
    except AtpBridgeUnavailable:
        return False
    return _CLI_PATH.exists()

"""
Lyrie SDK — ATP bridge tests (`lyrie.atp_bridge`, `lyrie atp verify`/`status` CLI).

These exercise the Python -> bun/@lyrie/atp subprocess bridge end to end.
Skipped gracefully if `bun` isn't on PATH (same guard pattern used
elsewhere in this repo for optional-toolchain-dependent tests).

Lyrie.ai by OTT Cybersecurity LLC — MIT License.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lyrie import atp_bridge
from lyrie.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parents[3]
GEN_SCRIPT = REPO_ROOT / "packages" / "atp" / "src" / "cli.ts"

bun_available = shutil.which("bun") is not None
requires_bun = pytest.mark.skipif(not bun_available, reason="bun not installed")


def _gen_atp_fixture(tmp_path: Path, kind: str) -> Path:
    """
    Shell out to a tiny bun/TS snippet that issues a real ATP artifact using
    the reference @lyrie/atp implementation, so these tests exercise real
    signed artifacts rather than hand-rolled JSON.
    """
    out_path = tmp_path / f"{kind}.json"
    script = f"""
import {{ issueAic, signReceipt, attestState, buildTrustChain, makeScope }} from "{REPO_ROOT}/packages/atp/src/index";
import {{ sha256Hex }} from "{REPO_ROOT}/packages/atp/src/crypto";

const baseInput = () => ({{
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("p"),
  scope: makeScope({{ allowedTools: ["a"], maxSubAgentDepth: 1 }}),
  operatorId: "guy@lyrie.ai",
}});

const kind = "{kind}";
let out;
if (kind === "aic") {{
  out = issueAic(baseInput()).cert;
}} else if (kind === "aic-expired") {{
  out = issueAic({{ ...baseInput(), issuedAt: Date.now() - 10_000, ttlMs: 1_000 }}).cert;
}} else if (kind === "scope") {{
  out = makeScope({{ allowedTools: ["a"], maxSubAgentDepth: 0 }});
}} else if (kind === "trust-chain") {{
  const root = issueAic(baseInput());
  const child = issueAic({{ ...baseInput(), parentCertId: root.certId, scope: makeScope({{ allowedTools: ["a"], maxSubAgentDepth: 0 }}) }});
  out = buildTrustChain([root.cert, child.cert]);
}} else if (kind === "receipt") {{
  const r = issueAic(baseInput());
  const receipt = signReceipt({{
    cert: r.cert,
    privateKey: r.keyPair.privateKey,
    action: {{ tool: "a", params: {{}}, timestamp: 1 }},
    result: {{ success: true, summary: "ok", timestamp: 2 }},
  }});
  out = {{ artifact: receipt, cert: r.cert }};
}} else if (kind === "attestation") {{
  const r = issueAic(baseInput());
  const att = attestState({{
    cert: r.cert,
    privateKey: r.keyPair.privateKey,
    state: {{ systemPromptHash: "a", memoryHash: "b", toolCallHistoryHash: "c" }},
  }});
  out = {{ artifact: att, cert: r.cert }};
}} else if (kind === "malformed") {{
  const r = issueAic(baseInput());
  out = {{ ...r.cert, operatorId: "attacker@evil.test" }};
}}

await Bun.write("{out_path}", JSON.stringify(out, null, 2));
"""
    script_path = out_path.with_suffix(".gen.ts")
    script_path.write_text(script)
    proc = subprocess.run(
        ["bun", "run", str(script_path)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, f"fixture generation failed: {proc.stderr}"
    return out_path


@requires_bun
def test_is_available_true_when_bun_present() -> None:
    assert atp_bridge.is_available() is True


@requires_bun
def test_verify_file_valid_aic(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "aic")
    result = atp_bridge.verify_file(str(path))
    assert result.kind == "aic"
    assert result.valid is True


@requires_bun
def test_verify_file_expired_aic(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "aic-expired")
    result = atp_bridge.verify_file(str(path))
    assert result.valid is False
    assert result.code == "ATP_CERT_EXPIRED"


@requires_bun
def test_verify_file_scope(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "scope")
    result = atp_bridge.verify_file(str(path))
    assert result.kind == "scope"
    assert result.valid is True


@requires_bun
def test_verify_file_trust_chain(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "trust-chain")
    result = atp_bridge.verify_file(str(path))
    assert result.kind == "trust-chain"
    assert result.valid is True


@requires_bun
def test_verify_file_receipt(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "receipt")
    result = atp_bridge.verify_file(str(path))
    assert result.kind == "receipt"
    assert result.valid is True


@requires_bun
def test_verify_file_attestation(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "attestation")
    result = atp_bridge.verify_file(str(path))
    assert result.kind == "attestation"
    assert result.valid is True


@requires_bun
def test_verify_file_malformed_signature(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "malformed")
    result = atp_bridge.verify_file(str(path))
    assert result.valid is False
    assert result.code == "ATP_SIGNATURE_INVALID"


@requires_bun
def test_verify_file_unknown_shape_no_crash(tmp_path: Path) -> None:
    path = tmp_path / "unknown.json"
    path.write_text(json.dumps({"nonsense": True}))
    result = atp_bridge.verify_file(str(path))
    assert result.kind is None
    assert result.valid is False
    assert result.code == "ATP_MALFORMED"


@requires_bun
def test_get_status_never_raises_on_invalid_artifact(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "malformed")
    result = atp_bridge.get_status(str(path))
    assert result.valid is False  # verdict still reported, but no exception


def test_bridge_unavailable_raises_clear_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(atp_bridge.AtpBridgeUnavailable):
        atp_bridge.verify_file(str(tmp_path / "whatever.json"))


# ─── CLI subcommand tests (`lyrie-py atp verify` / `atp status`) ─────────────


@requires_bun
def test_cli_atp_verify_exit_0_for_valid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _gen_atp_fixture(tmp_path, "aic")
    code = cli_main(["atp", "verify", str(path), "--json"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["valid"] is True
    assert out["kind"] == "aic"


@requires_bun
def test_cli_atp_verify_exit_1_for_invalid(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "malformed")
    code = cli_main(["atp", "verify", str(path)])
    assert code == 1


@requires_bun
def test_cli_atp_status_exit_0_even_for_invalid(tmp_path: Path) -> None:
    path = _gen_atp_fixture(tmp_path, "malformed")
    code = cli_main(["atp", "status", str(path)])
    assert code == 0


def test_cli_atp_verify_bridge_unavailable_exits_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    path = tmp_path / "whatever.json"
    path.write_text("{}")
    code = cli_main(["atp", "verify", str(path), "--json"])
    assert code == 2

"""
Lyrie on Modal — serverless backend reference deployment.

Deploy:
    pip install modal
    modal token new                # one-time auth
    modal deploy deploy/modal/lyrie_modal.py

After deploy, point Lyrie at it from CI:
    LYRIE_BACKEND=modal
    MODAL_TOKEN_ID=<from `modal token list`>
    MODAL_TOKEN_SECRET=<from `modal token list`>
    LYRIE_MODAL_APP=lyrie-agent
    LYRIE_MODAL_FUNCTION=lyrie_scan

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import modal

app = modal.App("lyrie-agent")

# Lyrie's image: bun runtime + git + the lyrie-agent repo cloned at deploy
# time. For private deployments, pin a release tag via LYRIE_REF.
image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("git", "curl", "ca-certificates")
    .run_commands(
        "curl -fsSL https://bun.sh/install | bash",
        # bun installs to /root/.bun; symlink so PATH-less runs work.
        "ln -sf /root/.bun/bin/bun /usr/local/bin/bun",
    )
    .run_commands(
        "git clone --depth 1 https://github.com/overthetopseo/lyrie-agent.git /opt/lyrie",
        "cd /opt/lyrie && bun install --frozen-lockfile",
    )
)


@app.function(
    image=image,
    cpu=1.0,
    memory=1024,
    timeout=600,
    secrets=[modal.Secret.from_name("lyrie-secrets", required_keys=[])],
)
def lyrie_scan(payload: dict) -> dict:
    """
    Run a single Lyrie scan inside Modal.

    Expected `payload` shape (Lyrie BackendRunRequest):
        {
            "target":       "<git URL or rel path>",
            "scanMode":     "quick" | "full" | "recon" | "vulnscan" | "apiscan",
            "scope":        "diff" | "full",
            "diffBase":     "origin/main",
            "failOn":       "critical" | "high" | ...,
            "intelOffline": false,
            "env":          { "K": "v", ... },
        }

    Returns Lyrie's BackendRunResult JSON-shape:
        { callId, status, sarif, markdown, costUsd? }
    """
    inputs = payload.get("inputs", {})
    target = inputs.get("target", "")
    work = Path("/tmp/lyrie-target")
    work.mkdir(parents=True, exist_ok=True)

    # 1. Materialise target — git clone or assume already-mounted path.
    if isinstance(target, str) and target.startswith(("http://", "https://", "git@")):
        subprocess.run(
            ["git", "clone", "--depth", "30", target, str(work)],
            check=True,
        )
    elif target:
        # Caller uploaded a tarball or relied on an external mount; user
        # extension point. Default = scan /opt/lyrie itself (smoke test).
        work = Path(target) if Path(target).exists() else Path("/opt/lyrie")
    else:
        work = Path("/opt/lyrie")

    # 2. Translate the inputs into LYRIE_* env vars.
    env = {
        "LYRIE_TARGET": str(work),
        "LYRIE_SCAN_MODE": inputs.get("scanMode", "quick"),
        "LYRIE_SCOPE": inputs.get("scope", "diff"),
        "LYRIE_FAIL_ON": inputs.get("failOn", "high"),
        "LYRIE_OUTPUT_DIR": "/tmp/lyrie-runs",
    }
    if inputs.get("diffBase"):
        env["LYRIE_DIFF_BASE"] = inputs["diffBase"]
    if inputs.get("intelOffline"):
        env["LYRIE_INTEL_OFFLINE"] = "1"
    for k, v in (inputs.get("env") or {}).items():
        env[k] = str(v)

    # 3. Run Lyrie.
    proc = subprocess.run(
        ["bun", "run", "/opt/lyrie/action/runner.ts"],
        cwd="/opt/lyrie",
        env={**dict(__import__("os").environ), **env},
        capture_output=True,
        text=True,
        timeout=550,
    )

    sarif_path = Path("/tmp/lyrie-runs/lyrie.sarif")
    markdown_path = Path("/tmp/lyrie-runs/lyrie.md")
    sarif = sarif_path.read_text() if sarif_path.exists() else ""
    markdown = markdown_path.read_text() if markdown_path.exists() else proc.stdout

    return {
        "callId": modal.current_function_call_id() if hasattr(modal, "current_function_call_id") else None,
        "status": "pass" if proc.returncode == 0 else "fail",
        "sarif": sarif,
        "markdown": markdown[:65535],
        # Modal exposes runtime cost via the dashboard; surface a stub here.
        "costUsd": None,
    }


# Local smoke test:  `modal run deploy/modal/lyrie_modal.py::smoke`
@app.local_entrypoint()
def smoke() -> None:
    out = lyrie_scan.remote(
        {
            "inputs": {
                "target": "/opt/lyrie",
                "scanMode": "quick",
                "scope": "full",
                "failOn": "critical",
                "intelOffline": True,
            }
        }
    )
    print(json.dumps({"status": out["status"], "sarif_bytes": len(out["sarif"])}, indent=2))

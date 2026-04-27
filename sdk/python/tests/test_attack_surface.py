"""
Lyrie SDK — AttackSurfaceMapper tests.

Lyrie.ai by OTT Cybersecurity LLC.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lyrie import AttackSurfaceMapper


def _seed(workspace: Path, rel: str, content: str) -> None:
    p = workspace / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_mapper_signature(tmp_path: Path) -> None:
    surface = AttackSurfaceMapper(root=tmp_path).run()
    assert surface.signature == "Lyrie.ai by OTT Cybersecurity LLC"
    assert surface.mapper_version.startswith("lyrie-asm-py-")


def test_mapper_detects_http_routes(tmp_path: Path) -> None:
    _seed(tmp_path, "server.ts", '''
        import express from "express";
        const app = express();
        app.get("/api/users", handler);
        app.post("/api/login", loginHandler);
    ''')
    surface = AttackSurfaceMapper(root=tmp_path).run()
    routes = [e for e in surface.entry_points if e.kind == "http-route"]
    assert len(routes) >= 2


def test_mapper_detects_subprocess_and_file_reader(tmp_path: Path) -> None:
    _seed(tmp_path, "worker.py", '''
        import subprocess
        import os
        subprocess.run("echo hello", shell=True)
        with open("/tmp/data") as f:
            f.read()
    ''')
    surface = AttackSurfaceMapper(root=tmp_path).run()
    kinds = {e.kind for e in surface.entry_points}
    assert "subprocess" in kinds
    assert "file-reader" in kinds


def test_mapper_detects_env_consumers(tmp_path: Path) -> None:
    _seed(tmp_path, "config.py", '''
        import os
        api_key = os.getenv("LYRIE_API_KEY")
        db_url = os.environ["DATABASE_URL"]
    ''')
    surface = AttackSurfaceMapper(root=tmp_path).run()
    env = [e for e in surface.entry_points if e.kind == "env-consumer"]
    assert len(env) >= 1


def test_mapper_detects_auth_and_shield_boundaries(tmp_path: Path) -> None:
    _seed(tmp_path, "middleware.ts", '''
        function authenticate(req, res, next) {
            if (jwt.verify(req.headers.authorization)) next();
        }
        const guard = Shield();
        guard.scan_inbound(req.body);
    ''')
    surface = AttackSurfaceMapper(root=tmp_path).run()
    kinds = {b.kind for b in surface.trust_boundaries}
    assert "auth-gate" in kinds
    assert "shield-gate" in kinds


def test_mapper_flags_user_message_to_shell(tmp_path: Path) -> None:
    _seed(tmp_path, "danger.ts", '''
        import { execSync } from "node:child_process";
        function handle(req) {
            execSync(req.body.command);
        }
    ''')
    surface = AttackSurfaceMapper(root=tmp_path).run()
    flow = next((f for f in surface.data_flows
                 if f.source == "user-message" and f.sink == "shell"), None)
    assert flow is not None
    assert flow.risk >= 7


def test_mapper_collects_npm_dependencies(tmp_path: Path) -> None:
    pkg = {
        "name": "demo",
        "dependencies": {"@lyrie/core": "0.3.0", "express": "^4"},
        "devDependencies": {"typescript": "^5"},
    }
    _seed(tmp_path, "package.json", json.dumps(pkg))
    surface = AttackSurfaceMapper(root=tmp_path, deps_only=True).run()
    assert len(surface.dependencies) == 3
    assert all(d.ecosystem == "npm" for d in surface.dependencies)


def test_mapper_skips_ignore_file(tmp_path: Path) -> None:
    _seed(tmp_path, "legit.ts", 'app.get("/x", h);')
    _seed(tmp_path, "fixture.ts", '// lyrie-shield: ignore-file\napp.get("/y", h);')
    surface = AttackSurfaceMapper(root=tmp_path).run()
    files = {e.file for e in surface.entry_points}
    assert "legit.ts" in files
    assert "fixture.ts" not in files
    assert surface.files_ignored >= 1

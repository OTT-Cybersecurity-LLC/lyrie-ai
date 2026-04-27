"""
Lyrie SDK — Multi-Language Scanners tests.

Lyrie.ai by OTT Cybersecurity LLC.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lyrie import scan_files


def _seed(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_scan_signature(tmp_path: Path) -> None:
    r = scan_files(root=tmp_path)
    assert r.signature == "Lyrie.ai by OTT Cybersecurity LLC"


def test_python_subprocess_shell_true(tmp_path: Path) -> None:
    _seed(tmp_path, "a.py", 'subprocess.run(cmd, shell=True)')
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-py-shell-001") for f in r.findings)


def test_python_pickle_loads(tmp_path: Path) -> None:
    _seed(tmp_path, "a.py", "import pickle\npickle.loads(data)")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-py-pickle-001") for f in r.findings)


def test_python_yaml_load_without_safeloader(tmp_path: Path) -> None:
    _seed(tmp_path, "a.py", "import yaml\nyaml.load(stream)")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-py-yaml-load-001") for f in r.findings)


def test_python_yaml_safe_load_clean(tmp_path: Path) -> None:
    _seed(tmp_path, "a.py", "yaml.load(stream, Loader=yaml.SafeLoader)")
    r = scan_files(root=tmp_path)
    assert not any(f.id.startswith("lyrie-py-yaml-load-001") for f in r.findings)


def test_jsts_eval(tmp_path: Path) -> None:
    _seed(tmp_path, "a.ts", "const x = eval(req.body.expr);")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-jsts-eval-001") for f in r.findings)


def test_jsts_inner_html(tmp_path: Path) -> None:
    _seed(tmp_path, "a.tsx", "el.innerHTML = userInput;")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-jsts-xss-001") for f in r.findings)


def test_jsts_template_sql(tmp_path: Path) -> None:
    _seed(tmp_path, "a.ts", "await db.query(`SELECT * FROM u WHERE id = ${id}`)")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-jsts-sqli-001") for f in r.findings)


def test_go_insecure_skip_verify(tmp_path: Path) -> None:
    _seed(tmp_path, "a.go", "tls.Config{ InsecureSkipVerify: true }")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-go-tls-skip-verify-001") for f in r.findings)


def test_php_unserialize(tmp_path: Path) -> None:
    _seed(tmp_path, "a.php", "<?php $obj = unserialize($_POST['data']);")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-php-deserialize-001") for f in r.findings)


def test_php_dynamic_include(tmp_path: Path) -> None:
    _seed(tmp_path, "a.php", "<?php include($_GET['page']);")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-php-include-001") for f in r.findings)


def test_ruby_marshal_load(tmp_path: Path) -> None:
    _seed(tmp_path, "a.rb", "Marshal.load(payload)")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-rb-marshal-001") for f in r.findings)


def test_c_strcpy(tmp_path: Path) -> None:
    _seed(tmp_path, "a.cpp", "strcpy(dest, src);")
    r = scan_files(root=tmp_path)
    assert any(f.id.startswith("lyrie-cpp-strcpy-001") for f in r.findings)


def test_lyrie_shield_ignore_file_skips(tmp_path: Path) -> None:
    _seed(tmp_path, "annotated.py", "# lyrie-shield: ignore-file\nsubprocess.run('ls', shell=True)")
    r = scan_files(root=tmp_path)
    assert len(r.findings) == 0


def test_finding_has_full_metadata(tmp_path: Path) -> None:
    _seed(tmp_path, "a.py", "subprocess.run('echo ' + x, shell=True)")
    r = scan_files(root=tmp_path)
    f = r.findings[0]
    assert f.file == "a.py"
    assert f.line and f.line > 0
    assert f.category is not None
    assert f.cwe is not None
    assert f.evidence and "subprocess" in f.evidence

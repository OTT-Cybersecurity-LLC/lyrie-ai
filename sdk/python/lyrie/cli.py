"""
`lyrie-py` CLI — operator entry point for the Python SDK.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lyrie import (
    AttackSurfaceMapper,
    Finding,
    Shield,
    StagesValidator,
    __version__,
    scan_files,
)
from lyrie.threat_intel import ThreatIntelClient


def _print_header(title: str) -> None:
    print()
    print(f"🛡️  {title}  ·  Lyrie.ai by OTT Cybersecurity LLC")
    print("─" * 65)


def _shield(args: argparse.Namespace) -> int:
    shield = Shield()
    text = " ".join(args.text)
    verdict = shield.scan_recalled(text) if args.mode == "recalled" else shield.scan_inbound(text)
    print(json.dumps({
        "blocked": verdict.blocked,
        "severity": verdict.severity,
        "reason": verdict.reason,
        "signature": verdict.signature,
    }, indent=2))
    return 0 if not verdict.blocked else 1


def _understand(args: argparse.Namespace) -> int:
    surface = AttackSurfaceMapper(root=args.root).run()
    if args.json:
        from dataclasses import asdict
        print(json.dumps(asdict(surface), indent=2))
        return 0
    _print_header("Lyrie Attack-Surface Map")
    print(f"  root:          {surface.root}")
    print(f"  files seen:    {surface.files_inspected}  (ignored {surface.files_ignored})")
    print(f"  entries:       {len(surface.entry_points)}")
    print(f"  boundaries:    {len(surface.trust_boundaries)}")
    print(f"  flows:         {len(surface.data_flows)}")
    print(f"  dependencies:  {len(surface.dependencies)}")
    if surface.hotspots:
        print()
        print("🔥 Top hotspots")
        for h in surface.hotspots[:10]:
            print(f"  [{h.score:>2}] {h.file}")
            for r in h.reasons[:4]:
                print(f"        {r}")
    print()
    print(f"signature: {surface.signature}")
    print()
    return 0


def _scan_files(args: argparse.Namespace) -> int:
    report = scan_files(root=args.root)
    if args.json:
        from dataclasses import asdict
        print(json.dumps({
            "scanned_files": report.scanned_files,
            "findings": [asdict(f) for f in report.findings],
            "languages": report.languages,
            "signature": report.signature,
        }, indent=2))
        return 0
    _print_header("Lyrie Multi-Language Scan")
    print(f"  files scanned: {report.scanned_files}")
    print(f"  findings:      {len(report.findings)}")
    print(f"  languages:     {' '.join(f'{l}({n})' for l, n in report.languages)}")
    print()
    for f in report.findings[:50]:
        print(f"  [{f.severity.upper():>8}] {f.title}")
        print(f"             {f.file}:{f.line}")
    print()
    print(f"signature: {report.signature}")
    print()
    return 0


def _validate(args: argparse.Namespace) -> int:
    finding = Finding(
        id=args.id,
        title=args.title,
        severity=args.severity,
        description=args.description,
        file=args.file,
        line=args.line,
        cwe=args.cwe,
        category=args.category,  # type: ignore[arg-type]
        evidence=args.evidence,
    )
    validator = StagesValidator()
    v = validator.validate(finding)
    print(json.dumps({
        "confirmed": v.confirmed,
        "confidence": round(v.confidence, 2),
        "stages": [{"stage": s.stage, "passed": s.passed, "reason": s.reason}
                    for s in v.stages],
        "poc": v.poc.payload if v.poc else None,
        "remediation": v.remediation.summary if v.remediation else None,
        "signature": v.signature,
    }, indent=2))
    return 0


def _intel(args: argparse.Namespace) -> int:
    client = ThreatIntelClient(offline=args.offline)
    ads = client.get_advisories()
    if args.json:
        from dataclasses import asdict
        print(json.dumps([asdict(a) for a in ads], indent=2))
        return 0
    _print_header("Lyrie Threat-Intel")
    if not ads:
        print("  (no advisories — feed unreachable, offline, or empty)")
    else:
        for a in ads[:25]:
            kev = " 🚨 KEV" if a.kev.in_kev else ""
            print(f"  {a.cve}  [{a.severity.upper()}]{kev}  {a.title}")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lyrie-py",
        description=f"Lyrie Agent Python SDK CLI — Lyrie.ai by OTT Cybersecurity LLC (v{__version__})",
    )
    parser.add_argument("--version", action="version", version=f"lyrie-agent {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_shield = sub.add_parser("shield", help="Run text through the Shield")
    p_shield.add_argument("text", nargs="+")
    p_shield.add_argument("--mode", choices=("recalled", "inbound"), default="recalled")
    p_shield.set_defaults(func=_shield)

    p_und = sub.add_parser("understand", help="Lyrie Attack-Surface Mapper")
    p_und.add_argument("--root", default=".")
    p_und.add_argument("--json", action="store_true")
    p_und.set_defaults(func=_understand)

    p_scan = sub.add_parser("scan-files", help="Lyrie multi-language scanners")
    p_scan.add_argument("--root", default=".")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=_scan_files)

    p_val = sub.add_parser("validate-finding", help="Run a finding through Stages A–F")
    p_val.add_argument("--id", default="cli-1")
    p_val.add_argument("--title", default="CLI test finding")
    p_val.add_argument("--severity", default="high")
    p_val.add_argument("--description", default="Submitted via lyrie-py CLI")
    p_val.add_argument("--file")
    p_val.add_argument("--line", type=int)
    p_val.add_argument("--cwe")
    p_val.add_argument("--category", default="other")
    p_val.add_argument("--evidence", default="")
    p_val.set_defaults(func=_validate)

    p_intel = sub.add_parser("intel", help="Lyrie Threat-Intel feed")
    p_intel.add_argument("--offline", action="store_true")
    p_intel.add_argument("--json", action="store_true")
    p_intel.set_defaults(func=_intel)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

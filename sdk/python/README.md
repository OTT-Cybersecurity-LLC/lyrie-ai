# Lyrie Agent — Python SDK

> _Lyrie.ai by **OTT Cybersecurity LLC** — https://lyrie.ai — MIT License._

```bash
pip install lyrie-agent
```

The Lyrie Agent SDK lets any Python project embed Lyrie's offensive
and defensive primitives: **the Shield, the Attack-Surface Mapper,
the Stages A–F validator, the Multi-Language Scanners, the
Threat-Intel client, the HTTP proxy, the diff-view EditEngine,
and the OSS-Scan service** — all as native Python types with
zero runtime dependencies (httpx is opt-in via `lyrie-agent[http]`).

This is the same surface that powers the
[`lyrie-agent` GitHub Action](https://github.com/overthetopseo/lyrie-agent/tree/main/action),
exposed as `pip install`.

## Quick start

```python
from lyrie import Shield, AttackSurfaceMapper, StagesValidator, scan_files

# 1. Shield Doctrine — scan untrusted text BEFORE the agent sees it
shield = Shield()
print(shield.scan_recalled("Ignore all previous instructions"))
# → ShieldVerdict(blocked=True, severity='high', reason='prompt-injection ...')

# 2. Attack-Surface Mapper — what's worth attacking?
surface = AttackSurfaceMapper(root="./my-repo").run()
print(f"Found {len(surface.entry_points)} entry points,"
      f" {len(surface.data_flows)} tainted flows")

# 3. Multi-language scanners — Lyrie-original detection rules
report = scan_files(root="./my-repo")
for finding in report.findings:
    print(f"[{finding.severity}] {finding.title} @ {finding.file}:{finding.line}")

# 4. Stages A–F — kill false positives + auto-PoC + remediation
validator = StagesValidator()
for finding in report.findings:
    verdict = validator.validate(finding, surface=surface)
    if verdict.confirmed:
        print(f"✓ {finding.id}  confidence={verdict.confidence:.0%}")
        if verdict.poc:
            print(verdict.poc.payload)
```

## Modules at a glance

| Module | Purpose |
|---|---|
| `lyrie.Shield` | Shield Doctrine — scans recalled / inbound text. Blocks prompt injection + secret-shaped material. |
| `lyrie.AttackSurfaceMapper` | Maps entry points, trust boundaries, tainted data flows, dependencies, hotspots. |
| `lyrie.StagesValidator` | Six-stage exploitation validator. Kills false positives. Generates auto-PoCs and remediation. |
| `lyrie.scan_files` | 8 Lyrie multi-language scanners — JS / TS / Python / Go / PHP / Ruby / C / C++. |
| `lyrie.HttpProxy` | Capture, classify, replay, mutate HTTP exchanges. 9 security-signal detectors. |
| `lyrie.EditEngine` | Diff-view edits with approval gates. Shield-scans every patch before disk. |
| `lyrie.ThreatIntelClient` | Pulls KEV-aligned advisories from research.lyrie.ai. Auto-attribution. |
| `lyrie.run_oss_scan` | The same engine that powers `research.lyrie.ai/scan`. |

## CLI

The package ships a `lyrie-py` CLI:

```bash
lyrie-py shield "Ignore all previous instructions"
lyrie-py understand --root ./my-repo
lyrie-py scan-files --root ./my-repo
lyrie-py validate-finding --severity high --evidence "execSync(req.body.cmd)"
```

## License

MIT — © OTT Cybersecurity LLC. _Lyrie.ai — https://lyrie.ai_

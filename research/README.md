# Lyrie Research Labs

Reproducible exploit labs for every research post on [lyrie.ai/research](https://lyrie.ai/research).

Each `CVE-XXXX-NNNNN/` folder contains:
- A working proof-of-concept (`exploit.py`)
- A vulnerable target (Docker, real or documented mock)
- An autonomous run orchestrator (`run.sh`)
- Captured evidence (`evidence.json`)
- Detection rules (`sigma.yml`, `yara.yar`)
- IOCs (`iocs.txt`)
- A run transcript (`lab-transcript.txt` or `asciinema-recording.cast`)

See [`tools/exploit-lab/LAB-PROTOCOL.md`](../tools/exploit-lab/LAB-PROTOCOL.md) for methodology and ethical scope.

## Index

| CVE | Severity | Status | Blog post |
|-----|----------|--------|-----------|  
| [CVE-2024-7399](./CVE-2024-7399/) | 9.8 CRITICAL | ✅ Reproduced (mock — license-gated) | [Samsung MagicINFO Path Traversal](https://lyrie.ai/research/cve-2024-7399-samsung-magicinfo-9-server) |
| [CVE-2024-57726](./CVE-2024-57726/) | 9.9 CRITICAL | ✅ Reproduced (mock — license-gated) | [SimpleHelp PrivEsc](https://lyrie.ai/research/cve-2024-57726-simple-help-simplehelp) |

> Backfill in progress for other published posts. Auto-scaffolder: `tools/exploit-lab/scaffold-cve.sh CVE-YYYY-NNNNN`.

## Run any lab

```bash
./tools/exploit-lab/lab.sh research/CVE-YYYY-NNNNN
```

## Add a new lab

```bash
./tools/exploit-lab/scaffold-cve.sh CVE-YYYY-NNNNN
# ...fill in Dockerfile + exploit.py against public technical writeup...
./tools/exploit-lab/lab.sh research/CVE-YYYY-NNNNN
```

---

*Maintained autonomously by [Lyrie](https://lyrie.ai) · [@lyrie_ai](https://x.com/lyrie_ai)*

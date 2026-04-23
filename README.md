# Lyrie OMEGA — Autonomous Security Intelligence Platform

> **Lyrie.ai | OTT Cybersecurity LLC**  
> Proprietary & Confidential — All Rights Reserved

---

## Overview

**Lyrie OMEGA** is the autonomous offensive/defensive security research core of the Lyrie.ai platform. It powers the HEX Scanner, Lyrie Intel, and the full exploit feasibility pipeline — delivering world-class binary analysis, forensic investigation, and vulnerability validation capabilities.

This suite is a proprietary Lyrie.ai product. All components are developed and owned by OTT Cybersecurity LLC / Lyrie.ai.

---

## Components

### Agent Fleet + Expert Personas

**17 agents** → `agents/`

| Agent | Purpose | Lyrie Product |
|-------|---------|---------------|
| `crash-analysis-agent` | Orchestrates full C/C++ crash triage | Lyrie HEX Scanner |
| `crash-analyzer-agent` | Deep root-cause analysis with rr | Lyrie HEX Scanner |
| `crash-analyzer-checker-agent` | Validates crash analyses rigorously | Lyrie HEX Scanner |
| `coverage-analysis-generator-agent` | gcov coverage data generation | Lyrie HEX Scanner |
| `function-trace-generator-agent` | Function execution tracing | Lyrie HEX Scanner |
| `exploitability-validator-agent` | Multi-stage exploitability pipeline | Lyrie Core Engine |
| `offsec-specialist` | Offensive security operations agent | Lyrie OMEGA |
| `oss-evidence-verifier-agent` | Forensic evidence verification | Lyrie Intel |
| `oss-hypothesis-checker-agent` | Hypothesis validation | Lyrie Intel |
| `oss-hypothesis-former-agent` | Evidence-backed hypothesis formation | Lyrie Intel |
| `oss-investigator-gh-archive-agent` | GH Archive BigQuery forensics | Lyrie Intel |
| `oss-investigator-github-agent` | GitHub API + commit recovery | Lyrie Intel |
| `oss-investigator-ioc-extractor-agent` | IOC extraction from vendor reports | Lyrie Intel |
| `oss-investigator-local-git-agent` | Local git repository forensics | Lyrie Intel |
| `oss-investigator-wayback-agent` | Wayback Machine content recovery | Lyrie Intel |
| `oss-report-generator-agent` | Final forensic report generation | Lyrie Intel |

**10 expert personas** → `personas/`

| Persona | Use Case |
|---------|----------|
| `security_researcher` | Deep vulnerability validation |
| `exploit_developer` | Working PoC generation |
| `crash_analyst` | Binary crash + exploitability analysis |
| `patch_engineer` | Production-ready secure patches |
| `penetration_tester` | Web payload generation |
| `fuzzing_strategist` | AFL++ strategy optimization |
| `binary_exploitation_specialist` | Binary exploit code generation |
| `codeql_analyst` | CodeQL dataflow path validation |
| `codeql_finding_analyst` | CodeQL finding exploitability assessment |
| `offensive_security_researcher` | Mitigation bypass feasibility |

---

### Exploit Feasibility Engine

**50+ files** → `packages/`

| Component | Files | Purpose |
|-----------|-------|---------|
| `packages/exploit_feasibility/` | 36 | Binary mitigation analysis, exploitation path scoring |
| `packages/exploitability_validation/` | 12 | Multi-stage validation pipeline (Stages 0-E) |
| `packages/cvss/` | 4 | CVSS scoring utilities |
| `core/smt_solver/` | 8 | SMT-based constraint solving (z3) for one-gadget feasibility |

**Key API:**
```python
from packages.exploit_feasibility import analyze_binary, format_analysis_summary
result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

---

### Lyrie Intel — OSS Forensics

**40+ files** → `skills/lyrie-intel/`

Lyrie Intel is Lyrie's autonomous forensic investigation engine.

| Component | Purpose |
|-----------|---------|
| `skills/lyrie-intel/github-archive/` | GH Archive BigQuery skill |
| `skills/lyrie-intel/github-evidence-kit/` | Evidence collection, storage, and verification |
| `skills/lyrie-intel/github-commit-recovery/` | Recover "deleted" git commits |
| `skills/lyrie-intel/github-wayback-recovery/` | Recover content from Wayback Machine |
| `skills/lyrie-intel/orchestration/` | Multi-agent orchestration skill |
| `commands/oss-forensics.md` | Command definition for `lyrie-intel` command |

**Invocation:** `/lyrie-intel <research-question> [--max-followups 3]`

---

### Lyrie HEX Scanner Enhancement

**60+ files** → `skills/code-understanding/`, `packages/static-analysis/`, `packages/codeql/`, `engine/`

| Component | Files | Purpose |
|-----------|-------|---------|
| `skills/code-understanding/` | 5 skills | Code comprehension and attack surface mapping |
| `packages/static-analysis/` | 3 | Semgrep integration |
| `packages/codeql/` | 16 | CodeQL database management + analysis |
| `engine/semgrep/` | 30+ | Semgrep rules (crypto, injection, secrets, auth) |
| `engine/codeql/` | 1 | CodeQL suite definitions |

---

## Quick Start

### 1. Install dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Set environment variable
```bash
export LYRIE_DIR=/path/to/lyrie-omega-suite
```

### 3. Run exploit feasibility analysis
```python
import sys, os
sys.path.insert(0, os.environ["LYRIE_DIR"])

from packages.exploit_feasibility import analyze_binary, format_analysis_summary

result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

### 4. Use Lyrie Intel for forensics
```
/lyrie-intel "Investigate suspicious commits in owner/repo between July 10-15 2025"
```

### 5. Run code understanding
```
/understand /path/to/target --map
/understand /path/to/target --trace main
/understand /path/to/target --hunt "unsanitized user input"
```

---

## Architecture

```
lyrie-omega-suite/
├── OMEGA-BRAIN.md          ← System prompt for Lyrie OMEGA autonomous mode
├── README.md               ← This file
├── ARCHITECTURE.md         ← Detailed component architecture
├── requirements.txt        ← Python dependencies
├── agents/                 ← 17 Lyrie OMEGA agents
│   ├── crash-analysis-agent.md
│   ├── exploitability-validator-agent.md
│   ├── offsec-specialist.md
│   └── oss-*/...
├── personas/               ← 10 expert personas
│   ├── security_researcher.md
│   ├── exploit_developer.md
│   └── ...
├── packages/               ← Python analysis packages
│   ├── exploit_feasibility/
│   ├── exploitability_validation/
│   ├── cvss/
│   ├── static-analysis/
│   └── codeql/
├── core/
│   └── smt_solver/         ← SMT constraint solving
├── skills/
│   ├── lyrie-intel/        ← OSS Forensics (Lyrie Intel)
│   └── code-understanding/ ← Code comprehension skills
├── commands/
│   └── oss-forensics.md    ← Lyrie Intel command
└── engine/
    ├── semgrep/            ← Semgrep rules + SARIF tools
    └── codeql/             ← CodeQL suites
```

---

## License

Copyright 2026 OTT Cybersecurity LLC / Lyrie.ai. All rights reserved.  
Proprietary and confidential. Unauthorized use, reproduction, or distribution is strictly prohibited.

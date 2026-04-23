# Lyrie OMEGA — Architecture Reference

> **Lyrie.ai | OTT Cybersecurity LLC**  
> Proprietary & Confidential — All Rights Reserved  
> Autonomous Security Intelligence Platform — Component Architecture

---

## Overview

Lyrie OMEGA is architected as a modular autonomous security intelligence platform. Each subsystem is independently deployable and integrates with the Lyrie.ai core engine.

---

## Layer 1: Agent Fleet

The agent fleet consists of 17 specialized autonomous agents that coordinate for complex security operations.

### Security Analysis Agents

| Agent | Location | Product Integration | Capability |
|-------|----------|-------------------|------------|
| `crash-analysis-agent` | `agents/crash-analysis-agent.md` | Lyrie HEX Scanner | Orchestrates full C/C++ crash triage workflows |
| `crash-analyzer-agent` | `agents/crash-analyzer-agent.md` | Lyrie HEX Scanner | Deep root-cause analysis using rr deterministic replay |
| `crash-analyzer-checker-agent` | `agents/crash-analyzer-checker-agent.md` | Lyrie HEX Scanner | Rigorous validation of crash analyses |
| `coverage-analysis-generator-agent` | `agents/coverage-analysis-generator-agent.md` | Lyrie HEX Scanner | gcov coverage data collection and analysis |
| `function-trace-generator-agent` | `agents/function-trace-generator-agent.md` | Lyrie HEX Scanner | Function execution instrumentation and tracing |
| `exploitability-validator-agent` | `agents/exploitability-validator-agent.md` | Lyrie Core Engine | Multi-stage vulnerability exploitability pipeline |
| `offsec-specialist` | `agents/offsec-specialist.md` | Lyrie OMEGA | Offensive security research and operations |

### Lyrie Intel Agents

| Agent | Location | Capability |
|-------|----------|------------|
| `oss-evidence-verifier-agent` | `agents/oss-evidence-verifier-agent.md` | Forensic evidence verification via `store.verify_all()` |
| `oss-hypothesis-checker-agent` | `agents/oss-hypothesis-checker-agent.md` | Validates claims against verified evidence |
| `oss-hypothesis-former-agent` | `agents/oss-hypothesis-former-agent.md` | Evidence-backed hypothesis formation |
| `oss-investigator-gh-archive-agent` | `agents/oss-investigator-gh-archive-agent.md` | GH Archive BigQuery forensic queries |
| `oss-investigator-github-agent` | `agents/oss-investigator-github-agent.md` | GitHub API + deleted commit recovery |
| `oss-investigator-ioc-extractor-agent` | `agents/oss-investigator-ioc-extractor-agent.md` | IOC extraction from vendor reports |
| `oss-investigator-local-git-agent` | `agents/oss-investigator-local-git-agent.md` | Local repository forensic analysis |
| `oss-investigator-wayback-agent` | `agents/oss-investigator-wayback-agent.md` | Wayback Machine content recovery |
| `oss-report-generator-agent` | `agents/oss-report-generator-agent.md` | Final forensic report generation |

---

## Layer 2: Expert Personas

10 specialist personas that augment agent decision-making with domain expertise.

| Persona | Location | Domain |
|---------|----------|--------|
| `security_researcher` | `personas/security_researcher.md` | Vulnerability research methodology |
| `exploit_developer` | `personas/exploit_developer.md` | Working PoC development |
| `crash_analyst` | `personas/crash_analyst.md` | Binary crash and exploitability |
| `patch_engineer` | `personas/patch_engineer.md` | Secure patch generation |
| `penetration_tester` | `personas/penetration_tester.md` | Web application attacks |
| `fuzzing_strategist` | `personas/fuzzing_strategist.md` | AFL++ and fuzzing optimization |
| `binary_exploitation_specialist` | `personas/binary_exploitation_specialist.md` | Binary exploit techniques |
| `codeql_analyst` | `personas/codeql_analyst.md` | CodeQL dataflow analysis |
| `codeql_finding_analyst` | `personas/codeql_finding_analyst.md` | CodeQL finding assessment |
| `offensive_security_researcher` | `personas/offensive_security_researcher.md` | Mitigation bypass techniques |

---

## Layer 3: Analysis Engine (Python Packages)

### exploit_feasibility — Binary Exploit Analysis

**Location:** `packages/exploit_feasibility/` (36 files)

The exploit feasibility engine provides automated binary mitigation analysis and exploitation path scoring. It incorporates SMT-based constraint solving, ROP gadget analysis, and empirical verification of exploit primitives.

**Key modules:**
- `api.py` — Public API: `analyze_binary()`, `format_analysis_summary()`
- `analyzer.py` — Core binary analysis orchestrator
- `context.py` / `exploit_context.py` — Exploit context modeling
- `strategies.py` / `techniques.py` — Exploitation strategy selection
- `primitives.py` — Exploit primitive classification
- `mitigations.py` — Mitigation detection and impact assessment
- `constraints.py` — SMT constraint modeling
- `graph.py` — Exploitation path graph
- `config.py` — LyrieConfig with LYRIE_* environment variables

**API Usage:**
```python
from packages.exploit_feasibility.api import analyze_binary, format_analysis_summary

result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

### exploitability_validation — Multi-Stage Pipeline

**Location:** `packages/exploitability_validation/` (12 files)

Implements the 7-stage exploitability validation pipeline (Stages 0-F → 1).

**Stages:**
- Stage 0 — Inventory building (mechanical)
- Stage A → F — LLM-driven analysis stages
- Stage 1 — Final validated output (mechanical)

**Key modules:**
- `orchestrator.py` — Pipeline orchestration
- `agentic.py` — LLM agent coordination
- `checklist_builder.py` — Validation checklist generation
- `report.py` — Final report generation

### cvss — Scoring Utilities

**Location:** `packages/cvss/` (4 files)

CVSS v3.1 scoring calculator with automated base/temporal/environmental metric computation.

### static-analysis — Semgrep Integration

**Location:** `packages/static-analysis/` (3 files)

Semgrep-based static analysis with parallel rule execution, SARIF output, and registry pack management.

### codeql — Database + Query Engine

**Location:** `packages/codeql/` (16 files)

Full CodeQL workflow: database creation, language detection, build synthesis, query execution, and dataflow visualization.

**Key modules:**
- `agent.py` — Autonomous CodeQL analysis agent
- `database_manager.py` — Database lifecycle management
- `query_runner.py` — Query execution with LyrieConfig settings
- `dataflow_visualizer.py` — Dataflow path visualization
- `autonomous_analyzer.py` — Self-directed analysis

---

## Layer 4: SMT Solver Core

**Location:** `core/smt_solver/` (8 files)

Z3-based SMT constraint solver for one-gadget feasibility analysis and exploit constraint verification.

**Key modules:**
- `session.py` — SMT solving session management
- `bitvec.py` — Bitvector arithmetic for binary analysis
- `constraints.py` → `constraints` (via package)
- `witness.py` — Satisfying assignment extraction
- `config.py` — LyrieConfig integration
- `availability.py` — Z3 availability checks

---

## Layer 5: Lyrie Intel Skills

**Location:** `skills/lyrie-intel/`

Autonomous forensic investigation capabilities for OSS repository analysis.

| Skill | Location | Purpose |
|-------|----------|---------|
| GitHub Archive | `skills/lyrie-intel/github-archive/` | BigQuery GH Archive queries |
| GitHub Evidence Kit | `skills/lyrie-intel/github-evidence-kit/` | Evidence collection, storage, verification |
| GitHub Commit Recovery | `skills/lyrie-intel/github-commit-recovery/` | Recover deleted commits |
| GitHub Wayback Recovery | `skills/lyrie-intel/github-wayback-recovery/` | Recover content from Wayback Machine |
| Orchestration | `skills/lyrie-intel/orchestration/` | Multi-agent coordination |

**Evidence Kit internals (`github-evidence-kit/src/`):**
- `clients/` — GitHub API, GH Archive, Wayback, Git clients
- `collectors/` — Evidence collectors (API, local, archive, wayback)
- `verifiers/` — Evidence consistency verification
- `schema/` — Event and observation data models
- `store.py` — Evidence storage and retrieval
- `parsers.py` — Log and event parsing

---

## Layer 6: Code Understanding Skills

**Location:** `skills/code-understanding/`

Deep code comprehension for security research.

| Skill File | Mode | Purpose |
|-----------|------|---------|
| `SKILL.md` | Config | Gates, output format, configuration |
| `map.md` | `--map` | Attack surface mapping, entry points, trust boundaries |
| `trace.md` | `--trace` | Data flow tracing source → sink |
| `hunt.md` | `--hunt` | Variant pattern discovery |
| `teach.md` | `--teach` | Framework/library security explanation |

---

## Layer 7: Scanning Engine

**Location:** `engine/`

### Semgrep Rules (`engine/semgrep/`)

Custom Lyrie HEX Scanner rules organized by vulnerability category:

| Category | Rules |
|----------|-------|
| `crypto/` | Weak ciphers, bad IVs, weak hash, insecure KDF, bad PRNG, PKCS#1 v1.5 |
| `injection/` | SQL concat injection, command taint |
| `auth/` | TLS verification bypass |
| `deserialisation/` | Unsafe Java deserialization |
| `secrets/` | Hardcoded API keys |
| `sinks/` | SSRF detection |
| `filesystem/` | Path traversal |
| `flows/` | MAC-then-Encrypt ordering |
| `logging/` | Secret leakage in logs |

Plus cached Semgrep registry packs: `c.p.security-audit`, `c.p.owasp-top-ten`, `c.p.secrets`, `c.p.jwt`, `c.p.command-injection`, `c.p.xss`

### CodeQL Suites (`engine/codeql/suites/`)

CodeQL query suite definitions for security-focused analysis.

---

## Configuration

All configuration uses `LYRIE_*` environment variables via `LyrieConfig`:

| Variable | Purpose |
|----------|---------|
| `LYRIE_DIR` | Base Lyrie OMEGA directory |
| `LYRIE_CONFIG` | Configuration file path |
| `LYRIE_OUT_DIR` | Output directory override |
| `LYRIE_VERBOSE` | Enable verbose logging |
| `LYRIE_CACHE_DIR` | Cache directory |
| `LYRIE_TIMEOUT_*` | Timeout settings (FAST/NORMAL/MEDIUM/SLOW/MAX) |
| `LYRIE_CHECKSEC_PATH` | checksec binary path |
| `LYRIE_ROPGADGET_PATH` | ROPgadget binary path |
| `LYRIE_ONE_GADGET_PATH` | one_gadget binary path |

---

## Copyright

Copyright 2026 OTT Cybersecurity LLC / Lyrie.ai. All rights reserved.  
Proprietary and confidential. Unauthorized use, reproduction, or distribution is strictly prohibited.

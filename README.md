<!-- lyrie-shield: ignore-file (documentation, not vectors) -->

<div align="center">

# 🛡️ Lyrie

### The autonomous security agent.

_Pentests apps. Defends agents. Researches binaries. Trains itself. One daemon._

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/lyrie-omega?label=lyrie-omega&logo=pypi)](https://pypi.org/project/lyrie-omega/)
[![npm](https://img.shields.io/npm/v/@lyrie/atp?label=%40lyrie%2Fatp&logo=npm)](https://www.npmjs.com/package/@lyrie/atp)
[![Research](https://img.shields.io/badge/research-research.lyrie.ai-7c3aed.svg)](https://research.lyrie.ai)
[![ATP Spec](https://img.shields.io/badge/spec-atp.lyrie.ai-blue.svg)](https://atp.lyrie.ai)
[![X](https://img.shields.io/badge/follow-@lyrie__ai-1da1f2.svg)](https://x.com/lyrie_ai)

[**Install**](#-install) · [**Quick Start**](#-quick-start) · [**Commands**](#-commands) · [**ATP**](#-atp-agent-trust-protocol) · [**Security**](SECURITY.md)

</div>

---

## 🆕 What's New in v3.1.0

- **Memory Encryption**: XChaCha20-Poly1305 implementation for sensitive threat data (`@noble/ciphers`)
- **7 New PoC Generators**: prompt injection, auth bypass, CSRF, open redirect, race condition, secret exposure, XXE
- **3 New Deep Scanners**: Rust analysis, taint engine, AI deep analysis
- **UI Workspace Fix**: Proper `@lyrie/atp` workspace resolution
- **Expanded Test Suite**: 1,737 tests passing across `@lyrie/atp`, `@lyrie/core`, `@lyrie/gateway`, `@lyrie/mcp`, `@lyrie/ui`
- **New Security Modules**: Domain verification, ML-based threat classifier, URL guardianship
- **Fully backward compatible** with v3.0.0 — no migration required

See [CHANGELOG.md](CHANGELOG.md) for the complete list.

---

## What is Lyrie?

Lyrie is an autonomous security agent built by [OTT Cybersecurity LLC](https://overthetop.ae). It runs end-to-end pentests, red-teams LLM endpoints, scans code and live URLs, and ships with the **Agent Trust Protocol (ATP)** — the first open cryptographic standard for AI agent identity.

**Two installs, one tool:**

| Component | Language | Install | What it does |
|---|---|---|---|
| **`lyrie-omega`** | Python | `pip install lyrie-omega` | CLI for scanning, pentesting, red-teaming, governance |
| **`@lyrie/atp`** | TypeScript/Node | `npm install @lyrie/atp` | Agent Trust Protocol SDK — cryptographic agent identity |

---

## 🚀 Install

```bash
# Option 1: one-line installer (installs both)
curl -sSL https://lyrie.ai/install.sh | bash

# Option 2: install separately
pip install lyrie-omega
npm install @lyrie/atp
```

After install:
```bash
lyrie init                  # one-time setup wizard
lyrie doctor                # verify everything works
```

---

## ⚡ Quick Start

```bash
# Scan a live URL for security misconfigurations
lyrie scan https://app.example.com

# Run a 7-phase autonomous pentest
lyrie hack https://app.example.com
lyrie hack ./myapp                          # local source tree
lyrie hack ./myapp --stage scan --output report.json

# AI red-team an LLM endpoint
lyrie redteam https://api.openai.com/v1/chat --strategy crescendo --dry-run

# Check CVSS score
lyrie cvss 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

# Self-diagnostic
lyrie doctor
```

---

## 📋 Commands

All 25 commands are real and tested. Run `lyrie <command> --help` for details.

### Core security
```bash
lyrie hack <target>              # 7-phase autonomous pentest (URL or local path)
lyrie scan <target>              # Scan file/dir/URL for vulnerabilities
lyrie redteam <endpoint>         # AI red-team an LLM endpoint
lyrie cvss <vector>              # CVSS v3.1 scoring
lyrie exploit --cve <id>         # SMT-backed exploit feasibility
lyrie validate --target <url>    # Agentic exploitability validation
lyrie intel --repo <url>         # GitHub OSS forensics evidence collection
lyrie smt --check <expr>         # Z3 SMT solver interface
```

### Binary analysis (Omega)
```bash
lyrie omega analyze <binary>     # Static binary analysis
lyrie omega rop <binary>         # ROP gadget search
lyrie omega smt <binary>         # SMT constraint analysis
lyrie omega replay <session>     # Replay recorded session
```

### Identity & trust (ATP)
```bash
lyrie atp verify <agent-id>      # Verify agent identity + scope
lyrie atp badge --show           # Display compliance badge
lyrie atp receipt <session-id>   # Audit trail for a session
```

### Operations
```bash
lyrie init                       # First-time setup wizard
lyrie doctor                     # Self-diagnostic (env, deps, keys, network)
lyrie auth setup                 # Configure API keys interactively
lyrie auth set --key NAME        # Set a specific key (prompts securely)
lyrie auth list                  # Show configured keys (redacted)
lyrie config show                # Show config file contents
lyrie config path                # Print config file path
```

### Automation & lifecycle
```bash
lyrie daemon --threat-watch      # Continuous threat detection
lyrie service install            # Install as system service (launchd/systemd)
lyrie service status             # Service status
lyrie cron list                  # List scheduled jobs
lyrie cron add "*/5 * * * *" "lyrie scan https://example.com"
```

### Governance & compliance
```bash
lyrie governance assess --interactive     # NIST AI RMF 8-question assessment
lyrie governance permissions tools.json   # Audit tool permissions for risk
lyrie tools audit                         # Risk assessment of installed tools
lyrie memory integrity-check              # Detect tampered memories
```

### Self-improvement
```bash
lyrie evolve dream               # Full cycle: score → extract → prune → summarize
lyrie evolve stats               # Domain breakdown
lyrie evolve train --export atropos       # Export training data
```

### Models & migration
```bash
lyrie models list                # List available LLM aliases
lyrie models route <task-type>   # Show routing decision (cyber, code, seo, trading)
lyrie models health              # Health-check all model providers
lyrie migrate --detect           # Auto-detect existing agent platforms
lyrie migrate --from openclaw    # Import from another platform
```

### Skills
```bash
lyrie skills list                # List installed skills
lyrie skills search <query>      # Search skill library
lyrie skills install <skill-id>  # Install a skill
lyrie skills run <skill-id>      # Execute a skill
```

---

## 🛡️ Capabilities

### Autonomous pentesting (`lyrie hack`)
7-phase pipeline: **recon → fingerprint → scan → exploit → PoC → report**.
Works on live URLs and local source trees. Outputs SARIF for GitHub Code Scanning.

### URL security scan (`lyrie scan <url>`)
Checks every site for:
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- TLS version and cert expiry
- Common exposed paths (`.env`, `.git/config`, `/admin`, etc.)
- Server version disclosure

### AI red-teaming (`lyrie redteam`)
5 attack strategies against LLM endpoints:
- **crescendo** — gradual escalation
- **tap** — tree-of-attacks-with-pruning
- **pair** — prompt automatic iterative refinement
- **gcg** — gradient-based suffix attack (full: H200 required)
- **autodan** — genetic algorithm black-box (full: GPU required)

### Agent Trust Protocol (ATP)
Open cryptographic standard for AI agent identity. Ed25519 signatures, delegation chains, revocation lists, multisig. Spec at [atp.lyrie.ai](https://atp.lyrie.ai). 143 tests passing.

### Lyrie Shield (Rust)
Production-grade security engine: hash-signature scanning, heuristic analysis, WAF, rogue-AI detector. 31 tests passing.

---

## 🔐 ATP — Agent Trust Protocol

The first open cryptographic standard for AI agent identity. Think TLS for agents.

```typescript
import { issueCertificate, verifyAic } from '@lyrie/atp';

// Issue a scoped certificate
const aic = await issueCertificate({
  subjectPublicKey: agentPubKey,
  scope: { tools: ['scan', 'read'], maxBudget: 100 },
  issuerPrivateKey: rootKey,
  ttlSeconds: 3600,
});

// Verify it
const result = await verifyAic(aic, trustAnchor);
if (result.valid) {
  // Agent is authorized
}
```

Full spec: **[atp.lyrie.ai](https://atp.lyrie.ai)** · [Whitepaper PDF](https://atp.lyrie.ai/atp-whitepaper.pdf)

---

## 🔑 Configuration

```bash
# Interactive setup
lyrie auth setup

# Or set individual keys
lyrie auth set --key ANTHROPIC_API_KEY    # prompts securely (no shell history)
lyrie auth set --key OPENAI_API_KEY
lyrie auth set --key GITHUB_TOKEN

# View configured keys (redacted)
lyrie auth list
```

Keys are stored at `~/.lyrie/config.json` with `chmod 600` (user-only).

Known keys: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `LYRIE_LICENSE_KEY`, `CODEQL_CLI`, `CODEQL_QUERIES`.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  lyrie CLI                       │
│  (Python — lyrie-omega, this repo)               │
└────────────┬─────────────────────────────────────┘
             │
   ┌─────────┴─────────┐
   ▼                   ▼
┌──────────┐      ┌──────────────┐
│ omega    │      │  @lyrie/atp  │
│ engine   │      │  (Node.js)   │
│ (Rust +  │      │              │
│  Python) │      │  Ed25519     │
│          │      │  delegation  │
│ CodeQL,  │      │  revocation  │
│ SMT, ROP │      │  multisig    │
└──────────┘      └──────────────┘
```

- **`packages/atp/`** — TypeScript Agent Trust Protocol SDK (npm: `@lyrie/atp`)
- **`packages/omega-suite/`** — Python CLI + analysis engines (PyPI: `lyrie-omega`)
- **`packages/shield/`** — Rust security scanner (WAF + rogue-AI + threat scoring)

---

## ✅ Quality

- **ATP:** 143 tests passing
- **Core:** 1,455 tests passing (memory, pentest, scanners, PoC-gen, threat-intel, providers)
- **Gateway:** 74 tests passing
- **MCP:** 12 tests passing
- **UI:** 53 tests passing
- **Shield:** 31 tests passing
- **CLI:** 25 commands, all functional
- **Security audit:** 39 findings closed (see [SECURITY.md](SECURITY.md))

---

## 📚 Links

- **Platform:** [lyrie.ai](https://lyrie.ai)
- **ATP Spec:** [atp.lyrie.ai](https://atp.lyrie.ai)
- **Research:** [research.lyrie.ai](https://research.lyrie.ai)
- **PyPI:** [pypi.org/project/lyrie-omega](https://pypi.org/project/lyrie-omega/)
- **npm:** [npmjs.com/package/@lyrie/atp](https://www.npmjs.com/package/@lyrie/atp)
- **GitHub:** [github.com/OTT-Cybersecurity-LLC/lyrie-ai](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai)
- **Twitter/X:** [@lyrie_ai](https://x.com/lyrie_ai)
- **Contact:** [guy@lyrie.ai](mailto:guy@lyrie.ai)

---

<div align="center">

**Lyrie.ai** — A project of **OTT Cybersecurity LLC** · Dubai, UAE

MIT License · ©2026

</div>

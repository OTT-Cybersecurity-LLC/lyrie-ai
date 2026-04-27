<div align="center">

# 🛡️ Lyrie Agent

### The world's first autonomous AI agent with built-in cybersecurity.

_The agent that defends what it builds._

Lyrie is not just another AI assistant. It runs your operations and protects them in the same loop — every layer carries the **Lyrie Shield**, every patch passes the **Shield Doctrine**, every finding earns its severity through **Lyrie Stages A–F**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Native](https://img.shields.io/badge/Security-Native-green.svg)](SECURITY.md)
[![Research](https://img.shields.io/badge/research-research.lyrie.ai-7c3aed.svg)](https://research.lyrie.ai)
[![X](https://img.shields.io/badge/follow-@lyrie__ai-1da1f2.svg)](https://x.com/lyrie_ai)
[![CI](https://github.com/overthetopseo/lyrie-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/overthetopseo/lyrie-agent/actions/workflows/ci.yml)
[![CodeQL](https://github.com/overthetopseo/lyrie-agent/actions/workflows/codeql.yml/badge.svg)](https://github.com/overthetopseo/lyrie-agent/actions/workflows/codeql.yml)
[![Tests](https://img.shields.io/badge/tests-234%20passing-brightgreen.svg)](#-quality--tests)
[![Releases](https://img.shields.io/github/v/release/overthetopseo/lyrie-agent?include_prereleases&label=release)](https://github.com/overthetopseo/lyrie-agent/releases)

[**Install**](#-install) · [**GitHub Action**](#-lyrie-pentest-action) · [**Architecture**](#-architecture) · [**Shield Doctrine**](docs/shield-doctrine.md) · [**Research**](https://research.lyrie.ai)

🌐 **Localized:** [العربية](locales/README.ar.md) · [Deutsch](locales/README.de.md) · [Español](locales/README.es.md) · [Français](locales/README.fr.md) · [日本語](locales/README.ja.md) · [Português](locales/README.pt-BR.md) · [简体中文](locales/README.zh-CN.md)

</div>

---

## Why Lyrie?

Every AI agent platform treats security as an afterthought. Lyrie treats it as the foundation — and ships the receipts. Every advisory we publish on [research.lyrie.ai](https://research.lyrie.ai) is backed by a reproducible exploit lab and detection rules in this repo.

> **Cybersecurity isn't a plugin — it's Layer 1.**

### Highlights (current main, [`v0.2.4+`](CHANGELOG.md))

- 🛡️ **The Shield Doctrine** — every layer of Lyrie that touches untrusted text passes a Shield gate. ([`docs/shield-doctrine.md`](docs/shield-doctrine.md))
- 🔍 **Lyrie Attack-Surface Mapper** (`/understand`) — maps entry points, trust boundaries, tainted data flows, and ranked risk hotspots before any scanner runs.
- 🧪 **Lyrie Stages A–F Validator** — every finding earns its severity through six validation gates. Auto-PoCs for confirmed vulns. Auto-remediation summaries. Kills false positives at the source.
- 🌐 **Lyrie Multi-Language Vulnerability Scanners** — 8 purpose-built scanners (JS / TS / Python / Go / PHP / Ruby / C / C++) with 53 Lyrie-original detection rules covering OWASP Top 10 + CWE classics.
- 📡 **Lyrie Threat-Intel feed** — every PR finding auto-attributed against [research.lyrie.ai](https://research.lyrie.ai), CISA-KEV-aligned, with Lyrie Verdict surfaced inline. Bumps severity to critical when KEV-listed.
- 🆓 **Lyrie OSS-Scan service** — free public scan at `research.lyrie.ai/scan`. Submit any GitHub / GitLab / Bitbucket / Codeberg repo URL, get a Lyrie report (Mapper + Scanners + Stages A–F + auto-PoC) in seconds.
- 🚀 **Lyrie Pentest GitHub Action** — Shield-scans every PR, posts a single-comment-per-PR Markdown summary, uploads SARIF to Code Scanning, blocks merges on `fail-on` threshold.
- 🧠 **FTS5 cross-session memory** — bm25-ranked recall + LLM-summarized session digests, every snippet Shield-gated.
- ✏️ **Diff-view edits** with approval gates — `apply_diff` produces unified diffs, never overwrites whole files; Shield scans every patch *before* it touches disk.
- 🔌 **MCP adapter** (`@lyrie/mcp`) — Lyrie speaks fluent Model Context Protocol both as client and server.
- 🚪 **DM pairing** — unknown senders can't reach the agent without operator approval. Three modes: `open` / `pairing` / `closed`.
- 🩺 **`lyrie doctor`** — read-only environment, channel, and security self-diagnostic with `--json` for CI.

---

## ⚡ Install

### One-line install

```bash
curl -fsSL https://lyrie.ai/install.sh | bash      # macOS / Linux / WSL
irm https://lyrie.ai/install.ps1 | iex             # Windows
```

### From source

```bash
git clone https://github.com/overthetopseo/lyrie-agent.git
cd lyrie-agent
bun install
bun run doctor       # self-check
bun start            # boot the gateway
```

Lyrie ships with a [Bun](https://bun.sh)-first toolchain (Node 20+ also supported).

---

## 🚀 Lyrie Pentest Action

Drop Lyrie into any repo's CI:

```yaml
name: Lyrie Pentest
on: [pull_request]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  lyrie:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - uses: overthetopseo/lyrie-agent/action@v1
        with:
          scan-mode: quick
          scope: diff
          fail-on: high
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

You get:

1. **Diff-scoped Shield + Mapper scan** — only PR-changed files, zero noise on untouched code
2. **Stages A–F validation** — false positives killed before they hit the report
3. **Single PR comment** that updates in place (no spam)
4. **SARIF** auto-uploaded to GitHub Code Scanning (findings show as PR annotations)
5. **Workflow artifact** with full `report.md` + `report.json` + `lyrie.sarif`
6. **Job summary** rendered into the GitHub Actions step summary tab
7. **Non-zero exit on threshold** — block merges when configured as a required check

Full docs: [`action/README.md`](action/README.md).

---

## 🏛 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 4 · INTERFACE                                         │
│    CLI · Web · Desktop · iOS · Android · 23+ channels        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3 · AGENT ENGINE                                      │
│    Multi-model routing  ·  Sub-agent fleet                   │
│    Skill manager  ·  Self-improving loop                     │
│    EditEngine (diff-view + approval)                         │
│    MCP client + server  ·  Tool executor                     │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2 · MEMORY CORE                                       │
│    SQLite + WAL  ·  FTS5 cross-session recall                │
│    Self-healing  ·  Hourly auto-backup                       │
│    Sectioned dream cycle  ·  Pluggable summarizer            │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1 · THE SHIELD                                        │
│    Real-time threat detection  ·  Prompt-injection gate      │
│    DM pairing  ·  Path scoping  ·  Tool-call validation      │
│    Lyrie Attack-Surface Mapper  ·  Stages A–F Validator      │
│    KEV-driven threat-intel feed (research.lyrie.ai)          │
└─────────────────────────────────────────────────────────────┘
```

The Shield is not a wrapper. It runs underneath every other layer.

---

## 🛡️ The Shield Doctrine

> Every Lyrie surface that touches untrusted text passes a Shield gate. **No exceptions, no carve-outs.**

| Surface | Hook | Status |
|---|---|---|
| Channel inbound (DMs) | `evaluateDmPolicy` (router) | ✅ |
| Pairing greeting | `DmPairingManager.greet` → `scanInbound` | ✅ |
| Memory recall | `searchAcrossSessions` → `scanRecalled` | ✅ |
| MCP tool results | `McpRegistry.shieldFilter` | ✅ |
| Tool output (`untrustedOutput=true`) | `ToolExecutor.shieldFilterOutput` | ✅ |
| Skill output | `SkillManager.shieldFilter` | ✅ |
| Diff-view applied edits | `EditEngine.plan` → `scanRecalled` | ✅ |
| Attack-surface evidence | `buildAttackSurface` → `sanitizeEvidence` | ✅ |
| Pentest scan target input | `runner.ts` → `scanInbound` | ✅ |

Full rule: [`docs/shield-doctrine.md`](docs/shield-doctrine.md).

---

## 📦 Repo layout

| Path | What |
|---|---|
| [`packages/core/`](packages/core/) | Lyrie agent core — engine, memory, skills, tools, MCP, attack-surface mapper, Stages A–F validator, EditEngine, Shield Guard |
| [`packages/gateway/`](packages/gateway/) | Multi-channel gateway (Telegram / WhatsApp / Discord) with DM pairing |
| [`packages/mcp/`](packages/mcp/) | `@lyrie/mcp` — Model Context Protocol adapter |
| [`packages/shield/`](packages/shield/) | Lyrie Shield — Rust cybersecurity engine |
| [`packages/omega-suite/`](packages/omega-suite/) | Lyrie OMEGA — autonomous security intelligence backend powering [research.lyrie.ai](https://research.lyrie.ai) |
| [`packages/ui/`](packages/ui/) | Lyrie war-room dashboard (Next.js) |
| [`action/`](action/) | Lyrie Pentest GitHub Action |
| [`research/`](research/) | Reproducible CVE exploit labs (Dockerfile + PoC + Sigma + YARA + IOCs) |
| [`tools/exploit-lab/`](tools/exploit-lab/) | Lab orchestration framework |
| [`skills/`](skills/) | Lyrie skills (extensible, self-improving) |
| [`scripts/`](scripts/) | Operator CLIs: `doctor`, `pairing`, `mcp`, `edits`, `understand`, release helpers |
| [`docs/`](docs/) | Architecture, contributing, Shield Doctrine, channel guides |

---

## 🧠 Model support

Model-agnostic. Lyrie routes per task class automatically:

| Tier | Default model | Use |
|---|---|---|
| Brain | Claude Opus 4.7 | Strategy, complex reasoning |
| Coder | GPT-5.5 / GPT-5.4-Codex | Code generation, refactors |
| Reasoning | o4-mini | Step-by-step deliberation |
| Fast | Gemini 3.1 Flash / Haiku 4.5 | Quick lookups, classification |
| Bulk | MiniMax-M2.7-HS | Mass content, parallel batches |
| Local | Qwen / Gemma / Llama-local | Private, self-hosted |

Bring any model — Anthropic, OpenAI, Google, xAI, MiniMax, Ollama, or your own endpoint. No lock-in.

---

## 📡 Channels

Telegram · WhatsApp · Discord · Slack · Signal · iMessage · CLI · Webchat — connect Lyrie to wherever you already work. **DM pairing on by default for production deployments.**

---

## 🛠 Operator CLIs

```bash
bun run doctor                    # self-diagnostic (env, channels, security, deps)
bun run understand                # Lyrie Attack-Surface Map of any workspace
bun run scan <repoUrl>            # free Lyrie OSS-Scan against a public repo
bun run intel list                # list cached Lyrie Threat-Intel advisories
bun run intel scan-deps           # match research.lyrie.ai feed against package.json
bun run intel lookup CVE-2024-7399
bun run pairing list              # show pending DM pairing requests
bun run pairing approve <chan> <code>
bun run mcp list                  # list MCP-server tools available to Lyrie
bun run edits list                # show pending diff-view edits awaiting approval
bun run edits approve <planId>
```

### Lyrie OSS-Scan — free public scan

Any public repo, one command:

```bash
bun run scan https://github.com/<owner>/<repo>
```

Lyrie clones the repo (`--depth 1`), runs the **Attack-Surface Mapper**, all eight **Multi-Language Scanners**, then **Stages A–F Validator** — returns the confirmed findings with auto-PoCs and Lyrie remediation summaries. Allowlisted hosts: `github.com`, `gitlab.com`, `bitbucket.org`, `codeberg.org`. Loopback / private addresses refused at the URL gate.

---

## 🌌 The Lyrie ecosystem

| Product | Status | What it does |
|---|---|---|
| **Lyrie Agent** (this repo) | OSS · MIT | Your autonomous AI operator + GitHub Action |
| **Lyrie Shield** | Native iOS/Android/macOS | Real-time device protection, anti-malware, anti-rogue-AI |
| **Lyrie Research** | [research.lyrie.ai](https://research.lyrie.ai) | KEV-driven verified threat intel, reproducible exploit labs |
| **Lyrie OMEGA** | OSS · MIT (in this repo) | Autonomous security-intelligence backend |
| **Lyrie SaaS** | [lyrie.ai](https://lyrie.ai) | Hosted Shield, WAF, scanner, breach monitoring |

Together: a complete digital guardian that operates **and** defends.

---

## ✅ Quality & tests

- **234 tests passing / 0 failing** across 19 test files
- Multi-platform CI (Node 20/22/24 × Ubuntu/macOS) + Rust Shield build
- Weekly CodeQL security analysis + Dependabot
- Pre-commit hooks: gitleaks, codespell, hygiene
- Lyrie Pentest Action runs **on this repo** every PR — Lyrie is its own first user

```bash
bun test packages/ action/
# → 234 pass · 0 fail · 619 expect()s
```

---

## 🔁 Migrating from another agent?

```bash
lyrie migrate --from openclaw    # ports memory, skills, config
lyrie migrate --from hermes      # ports skills + trajectory
lyrie migrate --from autogpt     # ports goals + memory
```

One command. Full memory + skills + config retained.

---

## 🤝 Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New CVE labs follow [`tools/exploit-lab/LAB-PROTOCOL.md`](tools/exploit-lab/LAB-PROTOCOL.md).

Code of Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). PRs that weaponize Lyrie tooling against unconsenting targets are rejected.

---

## 🔐 Security

See [`SECURITY.md`](SECURITY.md). Responsible disclosure goes to **security@lyrie.ai**.

Cybersecurity isn't a feature here — it's the product.

---

## 📜 License

MIT. Use it, fork it, build on it.

---

<div align="center">

**Lyrie.ai** — _Built by [OTT Cybersecurity LLC](https://overthetop.ae)_

[Research](https://research.lyrie.ai) · [@lyrie_ai](https://x.com/lyrie_ai) · [lyrie.ai](https://lyrie.ai) · [overthetop.ae](https://overthetop.ae)

© 2026 OTT Cybersecurity LLC. All rights reserved.

</div>

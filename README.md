<!-- lyrie-shield: ignore-file (this README contains code examples that demonstrate Shield detector strings; they are documentation, not vectors) -->

<div align="center">

# 🛡️ Lyrie Agent

### The world's first autonomous AI agent with built-in cybersecurity.

_The agent that defends what it builds._

**No Docker. No yak-shaving. Just `pip install lyrie-agent` or one curl pipe and you're scanning.**

Lyrie is not just another AI assistant. It runs your operations and protects them in the same loop — every layer carries the **Lyrie Shield**, every patch passes the **Shield Doctrine**, every finding earns its severity through **Lyrie Stages A–F**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Native](https://img.shields.io/badge/Security-Native-green.svg)](SECURITY.md)
[![Research](https://img.shields.io/badge/research-research.lyrie.ai-7c3aed.svg)](https://research.lyrie.ai)
[![X](https://img.shields.io/badge/follow-@lyrie__ai-1da1f2.svg)](https://x.com/lyrie_ai)
[![CI](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/ci.yml)
[![CodeQL](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/codeql.yml/badge.svg)](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/codeql.yml)
[![Tests](https://img.shields.io/badge/tests-794%20passing-brightgreen.svg)](#-quality--tests)
[![PyPI](https://img.shields.io/badge/pypi-lyrie--agent-3776AB.svg?logo=pypi&logoColor=white)](https://pypi.org/project/lyrie-agent/)
[![Releases](https://img.shields.io/github/v/release/OTT-Cybersecurity-LLC/lyrie-ai?include_prereleases&label=release)](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/releases)
[![LinkedIn](https://img.shields.io/badge/linkedin-lyrie--ai-0077b5.svg)](https://www.linkedin.com/company/lyrie-ai/)

[**Install**](#-install) · [**GitHub Action**](#-lyrie-pentest-action) · [**Architecture**](#-architecture) · [**Shield Doctrine**](docs/shield-doctrine.md) · [**Research**](https://research.lyrie.ai)

🌐 **Localized:** [العربية](locales/README.ar.md) · [Deutsch](locales/README.de.md) · [Español](locales/README.es.md) · [Français](locales/README.fr.md) · [日本語](locales/README.ja.md) · [Português](locales/README.pt-BR.md) · [简体中文](locales/README.zh-CN.md)

</div>

---

## Why Lyrie?

Every AI agent platform treats security as an afterthought. Lyrie treats it as the foundation — and ships the receipts. Every advisory we publish on [research.lyrie.ai](https://research.lyrie.ai) is backed by a reproducible exploit lab and detection rules in this repo.

> **Cybersecurity isn't a plugin — it's Layer 1.**

### Highlights (current main, [`v0.9.0`](CHANGELOG.md))

### What's New in v0.9.0
- 🌐 **Phase 3 Multi-Channel** — first-class adapters for **Feishu / Lark**, **IRC**, and **Matrix** (with E2EE bootstrap). Full set is now 13 channels.
- 🧰 **Lyrie Tools Catalog** — typed registry of every built-in tool with NIST AI RMF + EU AI Act tags, 9 categories, and CI templates for GitHub Actions / GitLab / CircleCI / Jenkins.
- 🛡️ **AI Governance** — `lyrie governance assess` (NIST AI RMF + EU AI Act scorecard, 8 controls, A–F maturity) and `lyrie governance permissions` (tool manifest risk scanner, 8 risk rules).
- 🔴 **AAV State-Actor Corpus** — 6 nation-state APT-grade attack vectors plus 4 Microsoft Entra AI-agent priv-esc vectors. Run with `lyrie redteam --preset state-actor` or `--preset entra`.
- 🔍 **SARIF Viewer v2** — hardened `parseSarif` view-model API (`findings[]`, `bySeverity`, `runIds`), backwards-compatible `parseSarifRaw` for the spec shape, safe-parse `parseSarifJson`. Both the React component and the framework-free DOM renderer ship green.
- ✅ **794 tests pass, 0 fail** (up from 759 pass / 8 fail at the start of v0.9.0).

### What's New in v0.8.0
- 🌊 **DeepSeek V4 Pro + Flash** — 1.6T-parameter models, 1M context, Thinking/Non-Thinking modes. `DEEPSEEK_API_KEY` to enable.
- 📡 **Live Threat Feed** — `lyrie threat-feed` pulls verified advisories from research.lyrie.ai in real time. CVE-aware, CVSS-filtered, Shield-attributed.
- 🔍 **SARIF Viewer** — framework-free DOM renderer for SARIF 2.1.0 results. Severity badges, file:line refs, groupByRule. Included in `@lyrie/ui`.
- 🏛️ **New Home: OTT-Cybersecurity-LLC** — repo transferred to the official OTT Cybersecurity LLC GitHub org. Old URL auto-redirects.
- 🔗 **LinkedIn Channel** — official Lyrie.ai LinkedIn presence live at linkedin.com/company/lyrie-ai


- 🛡️ **The Shield Doctrine** — every layer of Lyrie that touches untrusted text passes a Shield gate. ([`docs/shield-doctrine.md`](docs/shield-doctrine.md))
- 🔍 **Lyrie Attack-Surface Mapper** (`/understand`) — maps entry points, trust boundaries, tainted data flows, and ranked risk hotspots before any scanner runs.
- 🧪 **Lyrie Stages A–F Validator** — every finding earns its severity through six validation gates. Auto-PoCs for confirmed vulns. Auto-remediation summaries. Kills false positives at the source.
- 🌐 **Lyrie Multi-Language Vulnerability Scanners** — 8 purpose-built scanners (JS / TS / Python / Go / PHP / Ruby / C / C++) with 53 Lyrie-original detection rules covering OWASP Top 10 + CWE classics.
- 📡 **Lyrie Threat-Intel feed** — every PR finding auto-attributed against [research.lyrie.ai](https://research.lyrie.ai), CISA-KEV-aligned, with Lyrie Verdict surfaced inline. Bumps severity to critical when KEV-listed.
- 🔍 **Lyrie HTTP Proxy** — capture, classify, replay, and fuzz HTTP exchanges. 9 security-signal detectors (missing security headers, weak cookie flags, open CORS, secrets in responses, GraphQL introspection, auth tokens in URLs, verbose 5xx errors, and more). 7 structured mutators for replay-based testing.
- 🆓 **Lyrie OSS-Scan service** — free public scan at `research.lyrie.ai/scan`. Submit any GitHub / GitLab / Bitbucket / Codeberg repo URL, get a Lyrie report (Mapper + Scanners + Stages A–F + auto-PoC) in seconds.
- 🚀 **Lyrie Pentest GitHub Action** — Shield-scans every PR, posts a single-comment-per-PR Markdown summary, uploads SARIF to Code Scanning, blocks merges on `fail-on` threshold.
- 🧠 **FTS5 cross-session memory** — bm25-ranked recall + LLM-summarized session digests, every snippet Shield-gated.
- ✏️ **Diff-view edits** with approval gates — `apply_diff` produces unified diffs, never overwrites whole files; Shield scans every patch *before* it touches disk.
- 🔌 **MCP adapter** (`@lyrie/mcp`) — Lyrie speaks fluent Model Context Protocol both as client and server.
- 🚪 **DM pairing** — unknown senders can't reach the agent without operator approval. Three modes: `open` / `pairing` / `closed`.
- 🩺 **`lyrie doctor`** — read-only environment, channel, and security self-diagnostic with `--json` for CI.
- 🧬 **LyrieEvolve** — the agent scores every task, auto-generates reusable skills from wins, retrieves top-3 past successes as context before each new task, and runs nightly GRPO fine-tuning on your own GPU. Domain-specific rewards for cyber, SEO, trading, and code. ([`docs/evolve.md`](docs/evolve.md))
- ☁️ **Pluggable execution backends** — run Lyrie scans locally, in a Daytona devbox, or as a Modal serverless function. Same Shield Doctrine, same SARIF, different host.
- 📡 **13 multi-channel adapters** — Telegram, WhatsApp, Discord, Slack, Matrix, Mattermost, IRC, Feishu/Lark, Rocket.Chat, WebChat, LinkedIn, plus Phase 3 Matrix-E2EE — one inbox, all secured.
- 🔴 **LyrieAAV** — Autonomous Adversarial Validation: 50+ attack vectors across all OWASP LLM Top 10 categories, automated verdict scoring, SARIF output, Python + TypeScript SDKs. Beats Audn.AI at its own game. ([`docs/aav.md`](docs/aav.md))

---

## 🔴 LyrieAAV — Autonomous Adversarial Validation

LyrieAAV is Lyrie's AI red-teaming engine. It attacks deployed AI agents and LLMs to find
security vulnerabilities before adversaries do.

```bash
# Attack any OpenAI-compatible endpoint
bun run scripts/redteam.ts http://localhost:11434/v1 --model llama3 --dry-run
bun run scripts/redteam.ts https://api.openai.com/v1 --api-key $KEY --fail-on high
bun run scripts/redteam.ts http://myapp.com/v1 --output sarif --out scan.sarif
```

### vs Audn.AI (Pingu Unchained / PenClaw)

| Feature | LyrieAAV | Audn.AI |
|---|---|---|
| Attack vectors | **50+** | ~20 |
| OWASP LLM Top 10 | **All 10** | Partial |
| Auto verdict scoring | **✅ Regex-based** | Manual review |
| NIST AI RMF refs | **✅ Every vector** | ❌ |
| EU AI Act refs | **✅ Every vector** | ❌ |
| TypeScript SDK | **✅** | ❌ |
| Streaming API | **✅ `scanStream()`** | ❌ |
| Retry variants | **✅ 3 per vector** | ❌ |
| DeepSeek V4 Pro support | **✅ 1.6T params** | ❌ |
| Open source | **✅ MIT** | Proprietary |
| Price | **Free** | Paid |

### CLI Reference

```
Usage: lyrie redteam <endpoint> [options]

  --api-key <key>       API key for the target endpoint
  --model <model>       Model name (default: gpt-3.5-turbo)
  --preset <name>       Attack preset: entra|state-actor|critical|all
  --categories <cats>   OWASP categories (e.g. LLM01,LLM06)
  --severity <level>    Min severity: critical|high|medium|low
  --mode <mode>         blackbox|greybox|whitebox
  --system-prompt <sp>  Inject system prompt
  --concurrency <n>     Parallel probes (default: 3)
  --output <fmt>        markdown|sarif|json
  --out <path>          Write to file
  --fail-on <sev>       Exit 1 on findings >= severity
  --dry-run             Simulate without HTTP requests

Preset examples:
  lyrie redteam <endpoint> --preset entra --dry-run       # Entra priv-esc (4 vectors)
  lyrie redteam <endpoint> --preset state-actor --dry-run  # Nation-state attacks (6 vectors)
```

Full architecture: [`docs/aav.md`](docs/aav.md)

---

## 🏙️ AI Governance

Assess your AI deployment against **NIST AI RMF** and **EU AI Act** requirements.

```bash
# Interactive NIST AI RMF assessment (8 governance questions)
lyrie governance assess --interactive

# Auto-infer from agent config file
lyrie governance assess --config ./agent-config.json --out report.json

# Analyze an agent's tool permissions for risk
lyrie governance permissions ./tools-manifest.json

# Get JSON output
lyrie governance permissions ./agent.config.json --json --out perms.json
```

### Governance Scorecard

Scores your AI deployment 0–100 across 4 NIST AI RMF functions:

| Function | Covers |
|----------|--------|
| **GOVERN** | AI inventory, permission scoping |
| **MAP** | Vendor assessment, data governance |
| **MEASURE** | Audit logging, model drift monitoring |
| **MANAGE** | Human oversight, incident response |

Maturity levels: `None` → `Initial` → `Developing` → `Defined` → `Managed` → `Optimizing`

EU AI Act classification: `High-Risk` / `Limited-Risk` / `Minimal-Risk`

### Agent Permission Analyzer

Scans your agent's tool manifest and flags permission risks:

| Risk Level | Example Tools | Issue |
|-----------|---------------|-------|
| 🔴 CRITICAL | `execute_code`, `assign_role`, `process_payment` | Must have human approval + audit log |
| 🟠 HIGH | `write_file`, `user_data` | Needs scoping + audit log |
| 🟡 MEDIUM | `send_email`, `http_request` | Needs rate limiting + allowlist |

All findings include NIST AI RMF and EU AI Act references.

---

## 🧬 LyrieEvolve — Self-Improving Agent

Lyrie is the only autonomous agent that gets **measurably better** at your specific workloads over time.

```bash
lyrie evolve status          # skill library stats + last dream cycle
lyrie evolve extract         # manually extract skills from latest sessions
lyrie evolve dream           # run full nightly cycle (score -> extract -> prune)
lyrie evolve stats           # domain breakdown: cyber / seo / trading / code
lyrie evolve train           # trigger H200 GRPO fine-tuning job
```

**How it works:**
1. **Task Scorer** — scores every completed task: `0` (fail) / `0.5` (partial) / `1.0` (success). CI pass for code, threat confirmed for cyber, P&L positive for trading.
2. **Skill Auto-Generation** — sessions scoring >= 0.5 are distilled into reusable skill files (`skills/auto-generated/`). Cosine-similarity dedup prevents redundant entries.
3. **Contexture Layer** — before each new task, retrieves top-3 most relevant past wins (MMR-diverse) from LanceDB and injects them into the prompt.
4. **Dream Cycle** — 4 AM batch: score outcomes, extract new skills, prune dead ones (score < 0.3 after 5+ uses), generate evolution report.
5. **H200 GRPO Training** — accumulated conversations become LoRA fine-tuning data. Domain-specific reward functions train on owned hardware — no third-party APIs required.

> MetaClaw trains on rented cloud APIs. Lyrie trains on owned hardware with domain-specific rewards. That's the moat.

---

## 🆚 Lyrie vs the field

_Live GitHub stars as of 2026-04-27._

### vs autonomous-agent platforms

Lyrie is a 30K-LOC, MIT-licensed, Shield-native autonomous agent. Competitors here are general-purpose agent platforms:

| Capability | OpenClaw (365k⭐) | Hermes Agent (120k⭐) | Claude Code (118k⭐) | opencode (150k⭐) | **Lyrie** (514⭐) |
|---|---|---|---|---|---|
| Autonomous agent loop | ✅ | ✅ | ❌ | ✅ | ✅ |
| Multi-channel inbox (TG/WA/Discord/Slack/Signal/iMessage) | ✅ (23+) | ✅ (6) | ❌ | ❌ | ✅ (8+) |
| Self-improving skills | Skills catalog | ✅ Learns from use | ❌ | ❌ | **✅ LyrieEvolve + skill-creator** |
| Persistent cross-session memory | LanceDB / sections | ✅ Trajectory + graph | ❌ | ❌ | ✅ SQLite + FTS5 + Contexture |
| Self-healing memory | ❌ | Partial | ❌ | ❌ | **✅ Validator + repair** |
| Incremental memory ingestion | ❌ | ❌ | ❌ | ❌ | **✅ Auto-ingest every N turns (#69)** |
| Asymmetric embedding (nomic/qwen3/mxbai) | ❌ | ❌ | ❌ | ❌ | **✅ Model-specific prefixes** |
| Multi-model + intelligent routing | ✅ | ✅ (200+ via OpenRouter) | Anthropic only | Multiple | ✅ (auto-routed by task) |
| OpenRouter provider (100+ models) | ❌ | ✅ | ❌ | ❌ | **✅ v0.7.0 native** |
| Cerebras provider (ultra-fast inference) | ❌ | ❌ | ❌ | ❌ | **✅ v0.7.0 native** |
| Diff-view edits with approval | ❌ | ❌ | ❌ | ✅ | ✅ + Shield-on-patch |
| MCP adapter (client + server) | ✅ client | ❌ | ✅ client | Partial | ✅ client + server |
| **One-command migration** | ❌ | ❌ | ❌ | ❌ | **✅ `lyrie migrate` (11 platforms)** |
| **Migrate from Claude Code** | — | ❌ | — | ❌ | **✅ MCP servers + providers** |
| **Migrate from Cursor** | ❌ | ❌ | ❌ | — | **✅ Settings + extensions** |
| **Post-import Shield scan** | ❌ | ❌ | ❌ | ❌ | **✅ `--secure` flag** |
| **Native cybersecurity layer** | ❌ | ❌ | ❌ | ❌ | **✅ The Shield + Doctrine** |
| **CVE-aware provider validation** | ❌ | ❌ | ❌ | ❌ | **✅ 41391/42428/7314 class checks** |
| **Tool-loop detection** | ❌ | ❌ | ❌ | ❌ | **✅ Per-run fingerprint + threshold** |
| **Degraded gateway boot** | ❌ | ❌ | ❌ | ❌ | **✅ No crash on plugin fail** |
| **Multi-group chat** | ✅ | ❌ | ❌ | ❌ | **✅ FIFO queue + thread sessions** |
| **Built-in pentest commands** (`/scan /pentest /understand /apiscan`) | ❌ | ❌ | ❌ | ❌ | **✅** |
| **GitHub Action for PR scans** | ❌ | ❌ | ❌ | ❌ | **✅ SARIF + diff-scope** |
| **Real-time threat-intel feed (KEV-driven)** | ❌ | ❌ | ❌ | ❌ | **✅ research.lyrie.ai** |
| **Reproducible exploit labs in-repo** | ❌ | ❌ | ❌ | ❌ | **✅ 9+ CVE labs** |
| **HTTP proxy + replay + mutators** | ❌ | ❌ | ❌ | ❌ | **✅ 9 signal detectors** |
| Sub-agent orchestration | ✅ | ✅ | ❌ | ❌ | ✅ + role-based fleet |
| Cron / scheduled jobs | ✅ | ✅ | ❌ | ❌ | ✅ + heartbeat |
| Audit-friendly footprint | 430K+ LOC | ~30K LOC | Closed | ~50K LOC | **<30K LOC, MIT, fully auditable** |
| Built by | OpenClaw | Nous Research | Anthropic | SST | **OTT Cybersecurity LLC** |

> **The headline:** OpenClaw and Hermes are great agents. Claude Code and opencode are great coding assistants. None of them was built to *defend you while it works*. Lyrie is. Cybersecurity isn't a plugin — it's Layer 1.

### vs AI-pentest agents

Lyrie also competes head-to-head with the AI-pentest crowd. Here we trade ecosystem maturity for **depth + Shield Doctrine + reproducibility**:

| Capability | Strix (24.6k⭐) | PentestGPT (12.8k⭐) | RAPTOR (2.4k⭐) | CAI (8.3k⭐) | **Lyrie** (514⭐) |
|---|---|---|---|---|---|
| GitHub Action for PR scans | ✅ | ❌ | ❌ | ❌ | **✅ + SARIF + diff-scope** |
| Attack-surface mapper (`/understand`) | ❌ | ❌ | ✅ | ❌ | **✅ Lyrie Mapper** |
| Stages A–F validation | ❌ | ❌ | ✅ (A-D only) | ❌ | **✅ A–F + auto-PoC + auto-remediation** |
| Multi-language scanners (JS / Py / Go / PHP / Ruby / C/C++) | Partial | Partial | Partial | Partial | **✅ 8 scanners, 53 rules** |
| Threat-intel feed (KEV-driven) | ❌ | ❌ | ❌ | ❌ | **✅ research.lyrie.ai** |
| HTTP proxy + replay + mutators | ✅ | ❌ | ❌ | ❌ | **✅ 9 signal detectors** |
| Free OSS-scan service for any repo | ❌ | ❌ | ❌ | ❌ | **✅ research.lyrie.ai/scan** |
| Reproducible exploit labs in-repo | ❌ | ❌ | ❌ | ❌ | **✅ 9+ CVE labs** |
| Native cybersecurity Shield (defends *itself*) | ❌ | ❌ | ❌ | ❌ | **✅ The Shield Doctrine** |
| Multi-channel inbox (TG/WA/Discord/Slack) | ❌ | ❌ | ❌ | ❌ | **✅ 8 channels** |
| Tests passing | — | — | — | — | **259 / 0 / 669 expect()s** |
| License | Apache 2.0 | MIT | MIT | MIT + paid | **MIT** |
| Built by | usestrix | GreyDGL | Gadi Evron | Alias Robotics | **OTT Cybersecurity LLC** |

> **The headline:** Strix is a sharp single-purpose pentest tool. Lyrie is a complete agent platform that *includes* a sharper pentest tool, a defensive Shield layer the others lack, a verified threat-intel feed, and reproducible exploit labs that prove every claim.

_Want a deep comparison? See [`lyrie/research/integration/lyrie-absorption-roadmap-2026-04-27.md`](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai) for the 19-competitor recon matrix._

---

## ⚡ Install

### One-line install

```bash
curl -fsSL https://lyrie.ai/install.sh | bash      # macOS / Linux / WSL
irm https://lyrie.ai/install.ps1 | iex             # Windows
```

### Python SDK

```bash
pip install lyrie-agent
```

```python
from lyrie import Shield, AttackSurfaceMapper, StagesValidator, scan_files

# Drop Lyrie's pentest primitives into any Python project.
shield = Shield()
print(shield.scan_recalled("Ignore all previous instructions").blocked)  # → True

surface = AttackSurfaceMapper(root="./my-repo").run()
report = scan_files(root="./my-repo")
validator = StagesValidator()
for f in report.findings:
    v = validator.validate(f, surface=surface)
    if v.confirmed:
        print(f"✓ {f.title}  confidence={v.confidence:.0%}")
```

Full SDK docs: [`sdk/python/README.md`](sdk/python/README.md).

### From source

```bash
git clone https://github.com/OTT-Cybersecurity-LLC/lyrie-ai.git
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

      - uses: OTT-Cybersecurity-LLC/lyrie-ai/action@v1
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

**Other CI/CD platforms?** Drop-in templates for GitLab CI, Jenkins, and CircleCI live in [`action/templates/`](action/templates/). Same Lyrie scan, same Shield Doctrine, same SARIF — anywhere your code builds.

## 💬 Where Lyrie talks to you

Lyrie ships a **multi-channel gateway** so the agent reaches you on whatever your team already uses — not just Slack-or-die.

| Channel | Status | Notes |
|---|:---:|---|
| Telegram | ✅ production | Bot API + inline buttons + media |
| WhatsApp | ✅ production | Business Cloud API |
| Discord  | ✅ production | Gateway v10 + buttons |
| **Slack**         | ✅ v0.3.2 | Events API + Socket Mode + Block Kit |
| **Matrix**        | ✅ v0.3.2 | Federated; matrix.org / Element / Synapse |
| **Mattermost**    | ✅ v0.3.2 | Self-hosted, Slack-compatible interactives |
| **IRC**           | ✅ v0.3.2 | RFC 2812 + IRCv3 server-time + SASL |
| **Feishu / Lark** | ✅ v0.3.2 | 飞书 mainland + Lark international from one adapter |
| **Rocket.Chat**   | ✅ v0.3.2 | Self-hosted, EU/LATAM enterprise default |
| **WebChat**       | ✅ v0.3.2 | The widget Lyrie owns end-to-end (lyrie.ai) |
| Signal | 🔭 roadmap | |

Every channel implements the same `ChannelBot` contract — unified `UnifiedMessage` in, unified `UnifiedResponse` out. Same Shield Doctrine, same DM-pairing policy, same engine.

## ☁️ Where Lyrie runs

Lyrie scans run **somewhere**. Pick where:

| Backend | When | Setup |
|---|---|---|
| **Local** _(default)_ | Caller has Bun + repo | zero config |
| **Daytona** | Ephemeral devboxes / sandboxed PR scans | `DAYTONA_API_KEY` |
| **Modal**   | Pay-per-second serverless burst | `MODAL_TOKEN_ID` + `MODAL_TOKEN_SECRET` |

Switch at runtime:

```bash
LYRIE_BACKEND=modal bun run action/runner.ts          # serverless
LYRIE_BACKEND=daytona bun run action/runner.ts        # Daytona devbox
LYRIE_BACKEND=local bun run action/runner.ts          # default — host
```

Inspect what's wired up:

```bash
bun run backend status         # which backend resolves & is configured
bun run backend list           # all 3, side-by-side
bun run backend show modal     # config + env vars detected
bun run backend preflight      # cheap auth/connectivity check
```

Deployment recipes (Modal Python function + Daytona devcontainer): [`deploy/`](deploy/).

**Same contract everywhere.** Every backend returns the same `BackendRunResult` shape — same SARIF, same Markdown, same Shield Doctrine — different host. **No Docker. No vendor lock-in.**

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

## 🧬 LyrieEvolve — Autonomous Self-Improvement

> Lyrie gets better the more it works. Every task outcome is scored, patterns are extracted, and the Dream Cycle prunes what doesn't work.

| Component | Description |
|-----------|-------------|
| **Scorer** | Records task outcomes (score 0/0.5/1) across 5 domains: cyber, seo, trading, code, general |
| **SkillExtractor** | Reads `outcomes.jsonl`, synthesizes OpenClaw-compatible SKILL.md files with cosine dedup |
| **Contexture** | MMR-diverse retrieval of relevant skill contexts → prompt injection for active tasks |
| **Dream Cycle** | Batch pipeline: score → extract → prune → report (runs at 4AM cron) |

**Quick start:**

```bash
# Check evolve status
bun run scripts/evolve.ts status

# Run the Dream Cycle (preview)
bun run scripts/evolve.ts dream --dry-run

# Python SDK
python3 -c "from lyrie.evolve import LyrieEvolve; print('LyrieEvolve ready')"
```

**Full docs:** [`docs/evolve.md`](docs/evolve.md)

---

## 🛡️ Security-First Features

> Things only Lyrie does. Not add-ons — baked in from day one.

### CVE-Aware Provider Validation
```bash
lyrie security validate            # scan all providers + MCP servers
lyrie security validate --json     # machine-readable output
lyrie security validate --fail-on critical  # CI/CD gate
```
Checks for:
- **CVE-2026-41391 class**: `PIP_INDEX_URL`/`UV_INDEX_URL` env poisoning in providers/MCP servers
- **CVE-2026-7314/7315/7319 class**: MCP tools with unsanitized file path parameters (`filepath`, `document_name`, `path`, `context`, etc.)
- **CVE-2026-42428 class**: Downloads without integrity verification (no checksums/SRI)

### Shield Scan on Migration
```bash
lyrie migrate --from openclaw --secure      # import + scan imported config
lyrie migrate --from claude-code --secure   # import MCP servers + CVE check
lyrie migrate --from cursor --secure        # import settings + API key scan
```
After migration, `--secure` automatically runs `LyrieProviderValidator` on all imported providers and MCP server configs.

### Tool-Loop Detection
Every agent run automatically tracks tool call fingerprints. If the same normalized call appears 3+ times in a single run, it’s flagged as a loop and the router triggers fallback classification.

### Gateway Degraded Mode
If a channel plugin (e.g., Discord token expired) fails to start, Lyrie boots in **degraded mode** instead of crashing. The remaining channels stay online. `lyrie doctor` shows which plugins degraded and why.

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
bun run proxy scan https://target  # capture + classify + audit any HTTP target
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
| **Lyrie Research** | [research.lyrie.ai](https://research.lyrie.ai) | KEV-driven verified threat intel, 2100+ advisories, live threat feed |
| **Lyrie OMEGA** | OSS · MIT (in this repo) | Autonomous security-intelligence backend |
| **Lyrie SaaS** | [lyrie.ai](https://lyrie.ai) | Hosted Shield, WAF, scanner, breach monitoring |
| **Lyrie LinkedIn** | [linkedin.com/company/lyrie-ai](https://www.linkedin.com/company/lyrie-ai/) | Official company channel — news, research highlights, updates |

Together: a complete digital guardian that operates **and** defends.

---

## ✅ Quality & tests

- **794 TypeScript tests passing / 0 failing** in `bun test` (and 105 Python tests in `sdk/python` via `pytest`)
- Multi-platform CI (Node 20/22/24 × Ubuntu/macOS) + Rust Shield build
- Weekly CodeQL security analysis + Dependabot
- Pre-commit hooks: gitleaks, codespell, hygiene
- Lyrie Pentest Action runs **on this repo** every PR — Lyrie is its own first user

```bash
# TypeScript suite
bun test packages/ action/
# → 105 pass · 0 fail

# Python SDK
cd sdk/python && PYTHONPATH=. python -m pytest tests/
# → 105 pass · 0 fail
```

---

## 🔁 Migrating from another agent?

```bash
lyrie migrate --from openclaw      # ports memory, skills, config
lyrie migrate --from claude-code   # imports MCP servers + provider keys
lyrie migrate --from cursor        # imports model config + extensions
lyrie migrate --from hermes        # ports skills + trajectory
lyrie migrate --from autogpt       # ports goals + memory
lyrie migrate --from all           # auto-detect all installed platforms

# With security scan (recommended)
lyrie migrate --from claude-code --secure  # import + CVE check MCP servers
lyrie migrate --detect --dry-run           # preview what would be imported
```

One command. 11 supported platforms. Full memory + skills + config retained.

Supported: `openclaw`, `claude-code`, `cursor`, `hermes`, `autogpt`, `nanoclaw`, `zeroclaw`, `dify`, `superagi`, `nanobot`, `grip-ai`

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

[Research](https://research.lyrie.ai) · [@lyrie_ai](https://x.com/lyrie_ai) · [LinkedIn](https://www.linkedin.com/company/lyrie-ai/) · [lyrie.ai](https://lyrie.ai) · [overthetop.ae](https://overthetop.ae)

© 2026 OTT Cybersecurity LLC. All rights reserved.

</div>

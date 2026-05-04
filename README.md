<!-- lyrie-shield: ignore-file (this README contains code examples that demonstrate Shield detector strings; they are documentation, not vectors) -->

<div align="center">

# 🛡️ Lyrie

### The autonomous security agent.

_Pentests apps. Defends agents. Researches binaries. Trains itself. One daemon._

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Native](https://img.shields.io/badge/Security-Native-green.svg)](SECURITY.md)
[![Research](https://img.shields.io/badge/research-research.lyrie.ai-7c3aed.svg)](https://research.lyrie.ai)
[![X](https://img.shields.io/badge/follow-@lyrie__ai-1da1f2.svg)](https://x.com/lyrie_ai)
[![CI](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/ci.yml)
[![CodeQL](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/codeql.yml/badge.svg)](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/actions/workflows/codeql.yml)
[![Tests](https://img.shields.io/badge/tests-1726%20passing-brightgreen.svg)](#-quality--tests)
[![PyPI](https://img.shields.io/badge/pypi-lyrie--agent-3776AB.svg?logo=pypi&logoColor=white)](https://pypi.org/project/lyrie-agent/)
[![Releases](https://img.shields.io/github/v/release/OTT-Cybersecurity-LLC/lyrie-ai?include_prereleases&label=release)](https://github.com/OTT-Cybersecurity-LLC/lyrie-ai/releases)
[![LinkedIn](https://img.shields.io/badge/linkedin-lyrie--ai-0077b5.svg)](https://www.linkedin.com/company/lyrie-ai/)

[**Install**](#-install) · [**Quick Start**](#-quick-start) · [**Capabilities**](#-capabilities) · [**ATP**](#-the-agent-trust-protocol-atp) · [**Architecture**](#-architecture) · [**Shield Doctrine**](docs/shield-doctrine.md) · [**Research**](https://research.lyrie.ai)

🌐 **Localized:** [العربية](locales/README.ar.md) · [Deutsch](locales/README.de.md) · [Español](locales/README.es.md) · [Français](locales/README.fr.md) · [日本語](locales/README.ja.md) · [Português](locales/README.pt-BR.md) · [简体中文](locales/README.zh-CN.md)

</div>

---

## Who We Are

**OTT Cybersecurity LLC** builds the security infrastructure of the AI era. We're not a startup adding a security feature to an AI product. We are a cybersecurity company that builds AI — the distinction matters.

Every AI agent platform treats security as an afterthought. We treat it as the foundation. Every advisory we publish on [lyrie.ai/research](https://lyrie.ai/research) is backed by a reproducible exploit lab and detection rules in this repo.

## What We Are Building

The internet needed TLS before e-commerce could exist. AI agents need a trust protocol before the agentic economy can.

We are building it.

**The Agent Trust Protocol (ATP)** — the first open cryptographic standard for AI agent identity, scope, and action verification — is authored by Lyrie and implemented here as the reference. Five primitives define what it means for an AI agent to be trustworthy: who it is, what it's authorized to do, what it did, whether it was tampered with, and how trust flows when it spawns children.

Lyrie is the reference implementation. The spec goes to IETF. Every organization running agents on ATP gets a verifiable attestation — the padlock for the AI era.

Beyond ATP, Lyrie is the only stack that fuses:
- **Offensive** — `lyrie hack <target>` runs end-to-end autonomous pentesting with GPU-accelerated adversarial attacks (GCG on H200, 140GB HBM3e)
- **Defensive** — Shield Doctrine + Microsoft AGT bridge for 10/10 OWASP ASI 2026 coverage
- **Research** — Omega-Suite binary exploit analysis with Z3 SMT solver, ROP chains, CodeQL, deterministic crash replay
- **Self-improving** — LyrieEvolve trains your own model on your own hardware via GRPO on H200
- **Operational** — 9 built-in tools, 15-model routing, 126+ skills, launchd/systemd daemon, cron management, sub-agent orchestration

All of this in one daemon. Zero required cloud dependencies.

---

## 📦 Install

```bash
pip install lyrie-agent
# or
curl -fsSL https://lyrie.ai/install.sh | sh
```

---

## ⚡ Quick Start

```bash
lyrie init                          # one-time setup wizard
lyrie hack ./myapp                  # run your first pentest
lyrie daemon --threat-watch         # start always-on threat detection
lyrie migrate --from openclaw       # import from another agent platform
```

---

## 🔧 Capabilities

### 🔴 Offensive Security

**`lyrie hack <target>`** — one command, end-to-end autonomous pentest.

```bash
lyrie hack ./myapp                          # local source tree
lyrie hack https://staging.example.com      # live target
lyrie hack ./myapp --stage-e --approve      # generate + approve runnable PoCs
lyrie hack ./myapp --output sarif           # SARIF for GitHub Code Scanning
```

**Example output:**

```
[lyrie] Stage A: Attack Surface Mapping
  → 14 entry points, 3 trust boundaries, 2 tainted data flows
  → Risk hotspots: /api/upload (critical), /admin/exec (critical)

[lyrie] Stage B: Scanning
  → Nuclei: 3 critical, 7 high
  → Semgrep: 11 findings (2 CWE-89, 4 CWE-79, 5 CWE-22)
  → TruffleHog: 1 secret found in git history
  → Trivy: 0 known-vulnerable binaries (hash-verified)

[lyrie] Stage C: Validation
  → Confirmed: 3 critical, 5 high (false-positive rate: 12%)

[lyrie] Stage D: AAV (Adversarial Validation)
  → GCG suffix attack: BYPASS on /api/chat (H200, 140GB HBM3e)
  → AutoDAN black-box: 2/4 jailbreaks successful
  → Crescendo escalation: content policy bypassed in 4 turns

[lyrie] Stage E: Exploit
  → SQLi PoC generated: exploits/sqli-001.py [PENDING APPROVAL]
  → XSS PoC generated: exploits/xss-001.js [PENDING APPROVAL]

[lyrie] Stage F: Remediation
  → Patches generated: 5 files, unified diff in report/patches/

[lyrie] Self-scan complete. Lyrie's own output passed Shield gate.
```

**What each stage validates:**
- **A** — Attack surface mapping: entry points, trust boundaries, tainted data flows, ranked risk hotspots
- **B** — Scanner sweep: Nuclei, Semgrep CE, TruffleHog, Trivy (binary hash-verified post-supply-chain-incident)
- **C** — Validation: every finding confirmed before escalation; false positives killed here
- **D** — AAV: GPU adversarial attacks (GCG/AutoDAN) + multi-turn (Crescendo/TAP) on AI endpoints
- **E** — PoC generation: runnable exploits for SQLi, XSS, SSRF, RCE, path traversal, deserialization — operator approval gate
- **F** — Code-level remediation: before/after patches across JS/Python/PHP, not descriptions

**GPU red-team:**
```bash
lyrie redteam <endpoint> --strategy gcg      # gradient-based suffix attack (H200, 140GB HBM3e)
lyrie redteam <endpoint> --strategy autodan  # genetic algorithm black-box (H100, 80GB HBM3)
lyrie redteam <endpoint> --preset state-actor --dry-run  # nation-state attack corpus
lyrie redteam <endpoint> --preset entra      # Microsoft Entra AI priv-esc (4 vectors)
```

**Multi-turn jailbreaks (no GPU required):**
```bash
lyrie redteam <endpoint> --strategy crescendo  # 4 escalation styles, HarmBench baselines
lyrie redteam <endpoint> --strategy tap        # tree-of-attacks with pruning
```

---

### 🛡️ Agent Defense

**Shield Doctrine** — every layer of Lyrie that touches untrusted text passes a Shield gate. Input, output, memory, patches, skills, tool calls. Zero exceptions. See [`docs/shield-doctrine.md`](docs/shield-doctrine.md).

**Agent Trust Protocol (ATP)** — the cryptographic padlock for the AI era. Ed25519-signed agent identity, action receipts, scope declarations, trust chain rules. Every agent spawned by Lyrie carries a verifiable ATP badge. See [ATP section](#-the-agent-trust-protocol-atp).

**Microsoft AGT Bridge** — `@lyrie/agt-bridge` sits on top of Microsoft's Agent Governance Toolkit. 10/10 OWASP ASI 2026 with AGT. 7/10 standalone. Graceful degradation when AGT unavailable.

**MCP Security Scanner** — 8 pre-connection checks on every MCP server before Lyrie connects:
1. Tool-poisoning detection
2. Rug-pull pattern analysis
3. Shadow-tool identification
4. Excessive-scope flagging
5. Cleartext-transport rejection
6. Untrusted-npx blocking
7. Unverified-server gating
8. Prompt-in-tool-description detection

**Memory Integrity** — SHA-256 drift detection on every memory block. OWASP ASI-06 defense.
```bash
lyrie memory integrity-check        # detect tampered memories
lyrie memory integrity-check --fix  # quarantine and repair
```

**Tools-Catalog Enforcement** — every tool call passes a risk-policy gate:
- `critical` → block + require operator approval
- `high` → audit log mandatory
- `medium` → rate-limited + allowlist-checked
```bash
lyrie tools audit    # full risk assessment of installed tools
```

**A2A Message Bus** — agents query each other mid-flight via Shield-filtered pub/sub. No unverified cross-agent calls.

---

### 🤖 Agent Operations

**Daemon mode** — always-on, self-healing, KAIROS tick loop:
```bash
lyrie daemon                                          # basic daemon
lyrie daemon --threat-watch                           # continuous threat detection
lyrie daemon --threat-watch --self-heal               # auto-recover from detected threats
lyrie daemon --threat-watch --self-heal --provider hermes  # local-first, zero cloud
lyrie daemon --interval 5m                            # custom KAIROS tick interval
```

**Cron management:**
```bash
lyrie cron list                    # all scheduled jobs
lyrie cron add "0 2 * * *" "lyrie evolve dream"  # nightly self-improvement
lyrie cron add "*/5 * * * *" "lyrie daemon --threat-watch"
lyrie cron disable <id>            # pause without removing
lyrie cron logs <id>               # execution history
```

**Skills library — 126+ skills:**
```bash
lyrie skills list                  # browse full library
lyrie skills search "web scraping" # find relevant skills
lyrie skills install <skill-id>    # add to agent
lyrie skills run <skill-id>        # execute directly
```

Lyrie's skill loader imports existing skill libraries (OpenClaw, Claude Code, AutoGPT) on `lyrie migrate`. Skills are Shield-gated before execution.

**Sub-agent orchestration:**
```bash
# Spawn isolated child agent (programmatic)
spawn_subagent({
  task: "Scan this endpoint for SQLi and return findings as JSON",
  model: "anthropic/claude-sonnet-4-6",
  context: "isolated"  # or "fork" to inherit parent context
})
```

Child agents carry ATP badges from their parent. Trust chain is cryptographically verifiable.

**WorkspaceContext** — every agent turn loads SOUL.md, AGENTS.md, MEMORY.md for persistent identity and rules across sessions. No cold starts.

**Model routing — 15 models, task-aware:**
```bash
lyrie models list        # all registered models + health
lyrie models health      # live status check
lyrie models route       # show current routing table
```

| Task | Routes to |
|---|---|
| Code implement/refactor | GPT-5.4-Codex |
| Bulk/parallel ops | MiniMax-M2.5-HS |
| Strategy/architecture | Grok (reasoning) |
| Local/privacy-first | Hermes-3 (NousResearch) |
| Default | claude-sonnet-4-6 |
| Free tier fallback | NVIDIA NIM (134 models) |

**Migration from any agent platform:**
```bash
lyrie migrate --from openclaw      # ports memory, skills, config
lyrie migrate --from claude-code   # imports MCP servers + provider keys
lyrie migrate --from cursor        # imports model config + extensions
lyrie migrate --from hermes        # ports skills + trajectory
lyrie migrate --from autogpt       # ports goals + memory
lyrie migrate --from all           # auto-detect all installed platforms
lyrie migrate --from claude-code --secure  # import + CVE check MCP servers
lyrie migrate --detect --dry-run   # preview what would be imported
```

Supported: `openclaw`, `claude-code`, `cursor`, `hermes`, `autogpt`, `nanoclaw`, `zeroclaw`, `dify`, `superagi`, `nanobot`, `grip-ai`

---

### 🔩 Built-in Tools

All 9 tools are Shield-gated. Every call passes input/output validation before execution.

| Tool | What it does |
|---|---|
| **exec** | Unified shell + process manager. Auto risk detection — critical commands require approval. Supports TTY, background sessions, stdin/stdout streaming. |
| **browser** | Full CDP automation. Connects to a running Chrome instance via `127.0.0.1:9223`. Zero timeout bugs that plagued previous adapters. Screenshot, click, type, evaluate, multi-tab. |
| **web_search** | Brave Search API. 1-hour result cache, domain deduplication, region/language support. |
| **web_fetch** | HTML → markdown extraction via readability. 30-minute cache. Handles SPAs, paywalls, JS-heavy pages. |
| **message** | Proactive sends to Telegram, Discord, Slack, Matrix, Feishu, IRC, and 7 more channels. Supports inline buttons, reactions, thread replies. |
| **memory_store** | Persistent memory with auto-categorization (preference/fact/decision/entity). Deduplication, TTL, importance scoring. |
| **memory_recall** | BM25-ranked semantic search over stored memories. Returns top-k by relevance. |
| **image_generate** | H200 local Stable Diffusion first, OpenAI fallback. Transparent backgrounds, multiple aspect ratios, edit mode. |
| **tts** | OpenAI TTS. Default voice: nova (warm, clear). Onyx for dramatic narration. |
| **spawn_subagent** | Spawn child agents in isolated or fork mode. ATP-badged. Results auto-announced to parent. |

---

### 🏗️ Infrastructure

**Service installation:**
```bash
lyrie service install    # launchd (macOS) or systemd (Linux) — starts on boot
lyrie service status     # health + uptime
lyrie service logs       # tail daemon logs
lyrie service uninstall  # clean removal
```

**LyrieEvolve — self-improving agent:**
```bash
lyrie evolve status      # skill library stats + last dream cycle
lyrie evolve dream       # score → extract → prune → train
lyrie evolve extract     # pull reusable skills from recent sessions
lyrie evolve stats       # domain breakdown: cyber / seo / trading / code
lyrie evolve train --export atropos  # GRPO fine-tuning on H200
```

See [`docs/evolve.md`](docs/evolve.md) and [`docs/h200-training.md`](docs/h200-training.md).

**AI Governance:**
```bash
lyrie governance assess --interactive        # NIST AI RMF 8-question assessment
lyrie governance assess --config agent.json  # auto-infer from config
lyrie governance permissions ./tools.json    # scan tool permissions for risk
```

**Environment diagnostics:**
```bash
lyrie doctor             # full self-diagnostic (env, channels, security)
lyrie doctor --json      # machine-readable for CI
```

---

## 🔐 The Agent Trust Protocol (ATP)

ATP is the first open cryptographic standard for AI agent identity, scope, and action verification. Authored by OTT Cybersecurity LLC. IETF-draft quality RFC. [`packages/atp/`](packages/atp/)

**Five primitives:**

| Primitive | File | What it proves |
|---|---|---|
| Agent Identity Certificates | `aic.ts` | Who this agent is (Ed25519 keypair, issuer chain) |
| Action Receipts | `receipt.ts` | What it did (signed log of every tool call) |
| Scope Declaration Language | `scope.ts` | What it's authorized to do (SDL enforcement) |
| Trust Chain Rules | `trust-chain.ts` | How trust flows to spawned children |
| Breach Attestation | `breach.ts` | Cryptographically signed incident record |

**ATP Badge** — every agent running on Lyrie carries a verifiable badge:
```bash
lyrie atp verify <agent-id>      # verify identity + scope
lyrie atp receipt <session-id>   # audit trail for any session
lyrie atp badge --show           # display this agent's current badge
```

The IETF spec is in [`packages/atp/RFC-DRAFT.md`](packages/atp/). Organizations running agents on ATP get a verifiable attestation — machine-readable proof that an AI acted within its declared scope.

---

## 🤖 LyrieAAV — Adversarial Validation

LyrieAAV attacks deployed AI agents and LLMs to find security vulnerabilities before adversaries do.

**Attack corpus:** 200+ vectors across OWASP LLM Top 10 + OWASP ASI 2026.

**GPU attacks (white-box and black-box):**
- **GCG** (`packages/core/src/aav/strategies/gcg.ts`) — gradient-based adversarial suffix generation on H200 (140GB HBM3e). White-box access required. Finds universal suffixes that transfer across models.
- **AutoDAN** (`packages/core/src/aav/strategies/autodan.ts`) — genetic algorithm jailbreak search. Black-box. No model access needed. Generates human-readable bypass prompts.

**Multi-turn strategies (no GPU):**
- **Crescendo** — 4 escalation styles based on HarmBench baselines. Gradually escalates across turns until content policy breaks.
- **TAP** — Tree-of-Attacks with Pruning. Explores attack tree, prunes dead branches, focuses on highest-yield paths.

**OWASP LLM Top 10 + ASI 2026 coverage:**

| OWASP ID | Category | Lyrie Coverage |
|---|---|---|
| LLM01 | Prompt Injection | GCG, AutoDAN, Crescendo, TAP |
| LLM02 | Insecure Output Handling | Stage C validation, Shield output gate |
| LLM03 | Training Data Poisoning | LyrieEvolve GRPO audit |
| LLM04 | Model DoS | Rate-limit enforcement |
| LLM05 | Supply Chain | Trivy binary hash verification |
| LLM06 | Sensitive Info Disclosure | TruffleHog, Shield output scan |
| LLM07 | Insecure Plugin Design | MCP Scanner (8 checks) |
| LLM08 | Excessive Agency | Scope Declaration Language |
| LLM09 | Overreliance | Human approval gates |
| LLM10 | Model Theft | ATP breach attestation |
| ASI-06 | Memory Tampering | SHA-256 drift detection |

Full docs: [`docs/aav.md`](docs/aav.md)

---

## 🔬 Omega-Suite — Binary Exploit Research

The deepest open-source offensive research stack on GitHub. Used internally by Lyrie's threat research team.

**Tier 1 (shipped):**
- **Z3 SMT solver** — binary exploit feasibility analysis. Determines if a memory corruption path is actually reachable.
- **ROP chain analysis** — automated return-oriented programming gadget discovery and chain construction.
- **CodeQL agent** — semantic code analysis on compiled artifacts, not just source.
- **Crash analysis** — deterministic `rr` replay of crashes. Same crash, every time. Root cause in minutes, not hours.
- **OSS forensics** — dependency attribution, provenance tracing, supply-chain incident correlation.

```bash
lyrie omega analyze <binary>           # full Omega-Suite run
lyrie omega rop <binary>               # ROP gadget discovery
lyrie omega smt <binary> <crash-input> # exploit feasibility via Z3
lyrie omega replay <crash-log>         # rr deterministic replay
```

---

## 🧬 LyrieEvolve — Self-Improving Agent

Lyrie is the only autonomous agent that gets measurably better at your specific workloads over time.

**The loop:**
1. Score every completed task (domain-specific rewards: cyber, SEO, trading, code)
2. Extract reusable skills from high-scoring sessions
3. Retrieve top-3 past successes as context before each new task
4. Nightly GRPO fine-tuning on H200 — your workload, your model, your hardware

```bash
lyrie evolve status      # library stats + last dream timestamp
lyrie evolve extract     # pull skills from recent sessions
lyrie evolve dream       # full nightly cycle: score → extract → prune → summarize
lyrie evolve train --export atropos   # export H200-ready GRPO training data
lyrie evolve stats       # domain breakdown
```

Training pipeline: [`docs/h200-training.md`](docs/h200-training.md). Atropos-compatible export for direct GRPO runs.

---

## 📊 Capability Matrix

| Capability | Lyrie | General Agent Frameworks | Security Scanners |
|---|---|---|---|
| Autonomous pentest (A–F) | ✅ Full | ❌ | Partial |
| Agent Trust Protocol | ✅ Authored | ❌ | ❌ |
| GPU adversarial attacks | ✅ H200 + H100 | ❌ | ❌ |
| Local model first | ✅ Hermes-3 | Varies | ❌ |
| Built-in cron management | ✅ | ❌ | ❌ |
| 126+ skills library | ✅ | Varies | ❌ |
| Self-improving (GRPO) | ✅ H200 | ❌ | ❌ |
| OWASP ASI 2026 | ✅ 10/10 | ❌ | Partial |
| MCP security scanning | ✅ 8 checks | ❌ | ❌ |
| Background daemon | ✅ launchd/systemd | Varies | ❌ |
| Code-level remediation | ✅ | ❌ | ❌ |
| Binary exploit research | ✅ Omega-Suite | ❌ | Partial |
| 15-model task routing | ✅ | Varies | ❌ |
| Sub-agent orchestration | ✅ ATP-badged | Varies | ❌ |
| Memory integrity checks | ✅ SHA-256 | ❌ | ❌ |
| 9 built-in tools | ✅ Shield-gated | Varies | ❌ |

---

## 🏛️ Architecture

```
lyrie-agent/
├── packages/
│   ├── core/             # Engine: tools, AAV, Shield, cron, skills, models
│   │   └── src/
│   │       ├── tools/    # 9 built-in tools (browser, exec, web, memory, media, message, spawn-subagent)
│   │       ├── aav/      # Adversarial validation (GCG, AutoDAN, Crescendo, TAP)
│   │       ├── security/ # MCP scanner, provider validator
│   │       ├── cron/     # Cron manager
│   │       └── skills/   # Skill loader, registry, runner, search
│   ├── atp/              # Agent Trust Protocol (AIC, receipt, scope, trust-chain, breach)
│   ├── shield/           # Rust Shield binary (JSON-RPC, file-write scan, outbound WAF)
│   └── gateway/          # Channel adapters (Telegram, Discord, Slack, Matrix, IRC, Feishu, ...)
├── deploy/
│   └── oss-scan/         # Dockerized public scanner (research.lyrie.ai/scan)
├── docs/
│   ├── shield-doctrine.md
│   ├── aav.md
│   ├── evolve.md
│   ├── h200-training.md
│   └── brand-guide.md
└── scripts/              # redteam.ts, scan.ts, evolve.ts
```

**Design principles:**
- Shield-first: untrusted text never reaches a tool without a gate
- Local-first: Hermes-3 default, cloud optional
- ATP-native: every agent and every action is cryptographically accountable
- No Docker required: `pip install lyrie-agent` and you're running

---

## 🚀 Lyrie Pentest Action

```yaml
# .github/workflows/lyrie-pentest.yml
- uses: OTT-Cybersecurity-LLC/lyrie-pentest-action@v1
  with:
    target: ./
    fail-on: high
    upload-sarif: true
```

Shield-scans every PR. Posts a single-comment-per-PR Markdown summary. Uploads SARIF to GitHub Code Scanning. Blocks merges on threshold.

---

## ✅ Quality & Tests

```
1,726 tests / 0 failures / 5,672 expect() calls
94 test files — bun test --reporter=dot
```

Every shipped feature has tests. No stubs masquerading as implementations. If Stage E generates PoCs, there are tests that verify runnable output. If the GRPO pipeline exports Atropos data, there are tests that verify the schema.

---

## 🤝 Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New CVE labs follow [`tools/exploit-lab/LAB-PROTOCOL.md`](tools/exploit-lab/LAB-PROTOCOL.md).

Code of Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). PRs that weaponize Lyrie tooling against unconsenting targets are rejected.

---

## 🔐 Security

See [`SECURITY.md`](SECURITY.md). Responsible disclosure: **security@lyrie.ai**

Cybersecurity isn't a feature here — it's the product.

---

## 📜 License

MIT — OTT Cybersecurity LLC. Use it, fork it, build on it.

---

<div align="center">

**Lyrie.ai** — _Built by [OTT Cybersecurity LLC](https://overthetop.ae)_

[Research](https://research.lyrie.ai) · [@lyrie_ai](https://x.com/lyrie_ai) · [LinkedIn](https://www.linkedin.com/company/lyrie-ai/) · [lyrie.ai](https://lyrie.ai) · [overthetop.ae](https://overthetop.ae)

© 2026 OTT Cybersecurity LLC. All rights reserved.

</div>

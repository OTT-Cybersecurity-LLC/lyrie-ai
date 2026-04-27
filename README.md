# 🛡️ Lyrie Agent

**The world's first autonomous AI agent with built-in cybersecurity.**

Lyrie is not just another AI assistant. It's a guardian that runs your operations and protects them in the same loop.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Native](https://img.shields.io/badge/Security-Native-green.svg)](SECURITY.md)
[![Research](https://img.shields.io/badge/research-research.lyrie.ai-7c3aed.svg)](https://research.lyrie.ai)
[![X](https://img.shields.io/badge/follow-@lyrie__ai-1da1f2.svg)](https://x.com/lyrie_ai)
[![CI](https://github.com/overthetopseo/lyrie-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/overthetopseo/lyrie-agent/actions/workflows/ci.yml)
[![CodeQL](https://github.com/overthetopseo/lyrie-agent/actions/workflows/codeql.yml/badge.svg)](https://github.com/overthetopseo/lyrie-agent/actions/workflows/codeql.yml)

> 🌐 **Localized READMEs** (community translations welcome): [العربية](locales/README.ar.md) · [Deutsch](locales/README.de.md) · [Español](locales/README.es.md) · [Français](locales/README.fr.md) · [日本語](locales/README.ja.md) · [Português](locales/README.pt-BR.md) · [简体中文](locales/README.zh-CN.md)

---

## Why Lyrie?

Every AI agent platform treats security as an afterthought. Lyrie treats it as the foundation — and ships the receipts: every advisory we publish on [research.lyrie.ai](https://research.lyrie.ai) is backed by a reproducible exploit lab + detection rules in this repo.

### Lyrie vs the field — head-to-head (April 2026)

Compared against the **latest** releases at the time of writing:
**OpenClaw `2026.4.23`** · **Hermes Agent `v0.10.0` (2026.4.16)** · **Claude Code `2.1.x`**

| Capability | OpenClaw 2026.4.23 | Hermes 0.10.0 | Claude Code | **Lyrie** |
|---|---|---|---|---|
| Autonomous agent loop | ✅ | ✅ | ❌ | ✅ |
| Multi-channel (TG/WA/Discord/Signal/Slack/iMessage) | ✅ | ✅ | ❌ | ✅ |
| Self-improving skills | Skills catalog | ✅ Learns from use | ❌ | ✅ + skill-creator |
| Persistent cross-session memory | Lancedb / sections | ✅ Trajectory + graph | ❌ | ✅ Sectioned + dream cycle |
| Self-healing memory | ❌ | Partial | ❌ | **✅ Validator + repair** |
| Multi-model + intelligent routing | ✅ | ✅ (200+ via OpenRouter) | Anthropic only | ✅ (auto-routed by task class) |
| **Native cybersecurity layer** | ❌ | ❌ | ❌ | **✅ The Shield** |
| **Native device protection** (iOS/Android/Mac) | ❌ paired-device only | ❌ | ❌ | **✅ Lyrie Shield apps** |
| **Real-time threat intel feed** | ❌ | ❌ | ❌ | **✅ research.lyrie.ai (KEV-driven)** |
| **Reproducible exploit labs in-repo** | ❌ | ❌ | ❌ | **✅ `research/CVE-XXXX/` + `tools/exploit-lab/`** |
| **Built-in pentest/recon commands** (`/pentest /recon /vulnscan /apiscan`) | ❌ | ❌ | ❌ | **✅** |
| Sub-agent orchestration | ✅ | ✅ | ❌ | ✅ + role-based fleet (Brain/Muscle/Coder/Scout) |
| Browser control | Chrome DevTools MCP | ❌ | ❌ | ✅ + agent-browser skill |
| Cron / scheduled jobs | ✅ | ✅ | ❌ | ✅ + heartbeat protocol |
| RL training / trajectory export | ❌ | ✅ Atropos | ❌ | ✅ via OMEGA pipeline |
| Audit-friendly footprint | 430K+ LOC | ~30K LOC | Closed | **<30K LOC, MIT, fully auditable** |
| Built by | OpenClaw | Nous Research | Anthropic | **OTT Cybersecurity LLC** |

> **The headline:** OpenClaw and Hermes are great agents. Neither was built to *defend you while it works*. Lyrie is. Cybersecurity isn't a plugin — it's layer one.

## 📦 What's in this monorepo

| Path | Description |
|---|---|
| `packages/omega-suite/` | **Lyrie OMEGA** — Autonomous Security Intelligence Platform. CVE validator, CISA KEV watcher, multi-source intel firehose, and the publisher pipeline that powers [research.lyrie.ai](https://research.lyrie.ai). |
| `research/` | **Reproducible exploit labs.** Every published research advisory has a matching `CVE-XXXX-NNNNN/` folder with Dockerfile, working PoC, asciinema-style transcript, Sigma + YARA rules, and IOCs. See [`research/README.md`](./research/README.md). |
| `tools/exploit-lab/` | Autonomous exploit reproduction framework — `lab.sh` orchestrator, `scaffold-cve.sh`, [LAB-PROTOCOL.md](./tools/exploit-lab/LAB-PROTOCOL.md) (methodology + ethical scope). |
| `skills/` | Agent skills and capability modules (extensible, self-improving). |
| `packages/*` | Core runtime packages — agent loop, memory, channels, model routing. |
| `docs/` | Architecture, contributing, channel guides. |
| `scripts/`, `assets/`, `reports/` | Tooling, brand assets, and operator reports. |

## 🌐 Public channels

- **Research blog:** [research.lyrie.ai](https://research.lyrie.ai) — verified threat intelligence, 3+ source cross-validation, KEV-driven priority
- **X / Twitter:** [@lyrie_ai](https://x.com/lyrie_ai) — gold-verified
- **Main site:** [lyrie.ai](https://lyrie.ai)
- **Parent company:** [overthetop.ae](https://overthetop.ae) — OTT Cybersecurity LLC

## ⚡ Quick start

```bash
curl -fsSL https://lyrie.ai/install.sh | bash
```

Or manual:

```bash
git clone https://github.com/overthetopseo/lyrie-agent.git
cd lyrie-agent
pnpm install
pnpm start
```

## 🏛 Architecture

```
┌─────────────────────────────────────────────┐
│            LAYER 4: INTERFACE               │
│  CLI · Web · Desktop · iOS · Android        │
├─────────────────────────────────────────────┤
│            LAYER 3: AGENT ENGINE            │
│  Agent spawning · skills · self-improvement │
│  Multi-model routing · sub-agent fleet      │
├─────────────────────────────────────────────┤
│            LAYER 2: MEMORY CORE             │
│  Vector · graph · sectioned + dream cycle   │
│  Self-healing, versioned, full-text search  │
├─────────────────────────────────────────────┤
│            LAYER 1: THE SHIELD              │
│  Real-time threat detection · WAF           │
│  Anti-malware · behavioral · device protect │
│  Threat intel feed (research.lyrie.ai)      │
└─────────────────────────────────────────────┘
```

## 🧠 Model support

Model-agnostic. Lyrie routes per task class automatically:

| Tier | Model | Use |
|---|---|---|
| Brain | Claude Opus 4.7 | Strategy, complex reasoning |
| Coder | GPT-5.5 / GPT-5.4-Codex | Code generation, refactors |
| Fast | Gemini 3.1 Flash / Haiku 4.5 | Quick lookups, classification |
| Bulk | MiniMax-M2.7-HS | Mass content, parallel batches |
| Local | Qwen / Gemma / Llama-local | Private, self-hosted |

Bring any model — Anthropic, OpenAI, Google, xAI, MiniMax, Nous, or your own endpoint. No lock-in.

## 📡 Channels

Telegram · WhatsApp · Discord · Slack · Signal · iMessage · CLI · Webchat — connect Lyrie to wherever you already work.

## 🌌 The Lyrie ecosystem

| Product | What it does |
|---|---|
| **Lyrie Agent** (this repo) | Your autonomous AI operator |
| **Lyrie Shield** | Native cybersecurity protection across iOS, Android, Mac |
| **Lyrie Research** | [research.lyrie.ai](https://research.lyrie.ai) — verified threat intel, reproducible exploit labs |
| **Lyrie OMEGA** | Autonomous security intelligence backend ([packages/omega-suite/](./packages/omega-suite/)) |

Together: a complete digital guardian that operates *and* defends.

## 🔁 Migrating from OpenClaw or Hermes?

```bash
lyrie migrate --from openclaw   # ports memory, skills, config
lyrie migrate --from hermes     # ports skills + trajectory
```

One command. Full memory + skills + config retained.

## 🤝 Contributing

See [docs/contributing.md](docs/contributing.md). New CVE labs follow [LAB-PROTOCOL.md](./tools/exploit-lab/LAB-PROTOCOL.md).

## 🔐 Security

See [SECURITY.md](SECURITY.md). Responsible disclosure goes to **security@lyrie.ai**. Cybersecurity isn't a feature here — it's the product.

## 📜 License

MIT. Use it, fork it, build on it.

---

<p align="center">
  <strong>Built by <a href="https://overthetop.ae">OTT Cybersecurity LLC</a> · Powered by <a href="https://lyrie.ai">Lyrie</a> — the AI that protects.</strong>
  <br/>
  <a href="https://research.lyrie.ai">Research</a> ·
  <a href="https://x.com/lyrie_ai">@lyrie_ai</a> ·
  <a href="https://lyrie.ai">lyrie.ai</a> ·
  <a href="https://overthetop.ae">overthetop.ae</a>
</p>

<p align="center">
  © 2026 <a href="https://overthetop.ae">OTT Cybersecurity LLC</a>. All rights reserved.
</p>

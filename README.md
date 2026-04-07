# 🛡️ Lyrie Agent

**The world's first autonomous AI agent with built-in cybersecurity.**

Lyrie is not just another AI assistant. It's a guardian that protects your digital life while running your empire.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Native](https://img.shields.io/badge/Security-Native-green.svg)](SECURITY.md)

---

## Why Lyrie?

Every AI agent platform treats security as an afterthought. Lyrie treats it as the foundation.

| Feature | OpenClaw | Claude Code | Hermes | **Lyrie** |
|---------|----------|-------------|--------|-----------|
| Autonomous agent | ✅ | ❌ | ✅ | ✅ |
| Multi-channel | ✅ | ❌ | ✅ | ✅ |
| Self-improving | ❌ | ❌ | ✅ | ✅ |
| Self-healing memory | ❌ | ❌ | ❌ | **✅** |
| Native cybersecurity | ❌ | ❌ | ❌ | **✅** |
| Device protection | ❌ | ❌ | ❌ | **✅** |
| Threat intelligence | ❌ | ❌ | ❌ | **✅** |
| Auditable codebase | ❌ (430K lines) | ❌ | ✅ | **✅ (<30K)** |

## Quick Start

```bash
curl -fsSL https://lyrie.ai/install.sh | bash
```

Or install manually:

```bash
git clone https://github.com/lyrie-ai/lyrie-agent.git
cd lyrie-agent
pnpm install
pnpm start
```

## Architecture

```
┌─────────────────────────────────────────────┐
│            LAYER 4: INTERFACE               │
│  CLI + Web Dashboard + Desktop + Mobile     │
├─────────────────────────────────────────────┤
│            LAYER 3: AGENT ENGINE            │
│  Agent spawning, tools, self-improving      │
│  skills, model routing, coordination        │
├─────────────────────────────────────────────┤
│            LAYER 2: MEMORY CORE             │
│  Vector + Graph + Structured memory         │
│  Self-healing, versioned, searchable        │
├─────────────────────────────────────────────┤
│            LAYER 1: THE SHIELD              │
│  Real-time threat detection, anti-malware   │
│  WAF, behavioral analysis, device protect   │
└─────────────────────────────────────────────┘
```

## Model Support

Lyrie is model-agnostic with intelligent routing:

- **Brain**: Claude Opus 4.6 (complex reasoning)
- **Coder**: Grok 4.20 / GPT-5.4 Codex (code generation)
- **Fast**: Gemini 3.1 Flash / Haiku 4.5 (quick tasks)
- **Local**: Qwen 3.5 Max / Gemma 4 (self-hosted, private)

## Channels

Connect Lyrie to your life:

- Telegram
- WhatsApp
- Discord
- Slack
- Signal
- CLI

## The Lyrie World Pack

Lyrie Agent is part of the **Lyrie.ai ecosystem**:

- **Lyrie Agent** — Your autonomous AI operator (this repo)
- **Lyrie Shield** — Cybersecurity protection for all your devices
- **Lyrie Mobile** — iOS & Android companion apps

Together, they form a complete digital guardian.

## Migrating from OpenClaw?

```bash
lyrie migrate --from openclaw
```

We built a one-command migration tool that brings your memory, skills, and configuration.

## Contributing

See [CONTRIBUTING.md](docs/contributing.md)

## Security

See [SECURITY.md](SECURITY.md) — we take security seriously. That's literally our product.

## License

MIT — use it, fork it, build on it.

---

**Built by [OTT Cybersecurity LLC](https://lyrie.ai) — The AI that protects.**

© 2026 OTT Cybersecurity LLC. All rights reserved.

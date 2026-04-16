# Architecture

Lyrie Agent is built as a layered monorepo with four packages. Each layer has a clear responsibility and well-defined interfaces.

## System Overview

```
                        ┌──────────────────────────────────┐
                        │          USER / CLIENT           │
                        │  Telegram · Discord · WhatsApp   │
                        │       Signal · Slack · CLI       │
                        └──────────────┬───────────────────┘
                                       │
                        ┌──────────────▼───────────────────┐
                        │     📡  GATEWAY  (@lyrie/gateway) │
                        │                                   │
                        │  • Channel adapters (Telegram,    │
                        │    Discord, WhatsApp, Slack)      │
                        │  • Unified message format         │
                        │  • Rate limiting & auth           │
                        │  • Command dispatch               │
                        │  • Streaming updates              │
                        └──────────────┬───────────────────┘
                                       │
                        ┌──────────────▼───────────────────┐
                        │      ⚡  ENGINE  (@lyrie/core)    │
                        │                                   │
                        │  ┌─────────┐  ┌───────────────┐  │
                        │  │  Model  │  │     Tool      │  │
                        │  │  Router │  │   Executor    │  │
                        │  └────┬────┘  └───────┬───────┘  │
                        │       │               │          │
                        │  ┌────▼────┐  ┌───────▼───────┐  │
                        │  │ Providers│  │    Skills     │  │
                        │  │ Anthropic│  │ Self-improving│  │
                        │  │ OpenAI  │  │  Reusable     │  │
                        │  │ Google  │  │  Patterns     │  │
                        │  │ xAI     │  └───────────────┘  │
                        │  │ MiniMax │                      │
                        │  │ Ollama  │                      │
                        │  └─────────┘                      │
                        └──────────────┬───────────────────┘
                                       │
                ┌──────────────────────┼──────────────────────┐
                │                      │                      │
    ┌───────────▼──────────┐ ┌────────▼─────────┐ ┌─────────▼─────────┐
    │  🧠 MEMORY CORE      │ │  🛡️  SHIELD       │ │  🖥️  UI            │
    │                      │ │                   │ │  (@lyrie/ui)      │
    │  Layer 0: Archive    │ │  Input scanning   │ │                   │
    │  Layer 1: Master     │ │  Tool validation  │ │  Next.js 15       │
    │  Layer 2: Vector     │ │  Rogue AI detect  │ │  Dashboard        │
    │  Layer 3: Working    │ │  Malware scan     │ │  Memory viewer    │
    │  Layer 4: Healing    │ │  WAF              │ │  Shield status    │
    │                      │ │                   │ │  Agent management │
    └──────────────────────┘ │  Rust engine      │ └───────────────────┘
                             │  (lyrie-shield)   │
                             └───────────────────┘
```

## Package Details

### `@lyrie/core` — The Brain

The core package contains everything needed to run the agent without any UI or channel integration.

```
packages/core/
├── src/
│   ├── index.ts              # Entry point + re-exports
│   ├── config.ts             # Zod-validated configuration
│   ├── engine/
│   │   ├── lyrie-engine.ts   # Main agent runtime
│   │   ├── model-router.ts   # Task → model routing
│   │   ├── shield-manager.ts # Security layer (TS)
│   │   └── providers/        # AI provider adapters
│   │       ├── anthropic.ts
│   │       ├── openai.ts
│   │       ├── google.ts
│   │       ├── xai.ts
│   │       ├── minimax.ts
│   │       └── ollama.ts
│   ├── memory/
│   │   └── memory-core.ts    # 5-layer memory system
│   ├── tools/
│   │   └── tool-executor.ts  # Secure tool execution
│   ├── skills/
│   │   └── skill-manager.ts  # Self-improving skills
│   ├── channels/
│   │   └── gateway.ts        # Core channel interface
│   └── migrate/              # Platform migration tools
│       ├── index.ts
│       ├── openclaw.ts
│       ├── hermes.ts
│       └── ...
└── tests/                    # 66 tests, 249 assertions
```

#### Agent Loop

```
User Message
    │
    ▼
┌─ Shield.scanInput() ─── blocked? → return warning
│
├─ Memory.recall()        ← retrieve relevant context
│
├─ ModelRouter.route()    ← pick optimal model for task
│
├─ Model.complete()       ← generate response + tool calls
│
├─ Shield.validateToolCall() ── for each tool call
│   └─ ToolExecutor.execute() ── if approved
│
├─ Memory.store()         ← persist interaction
│
└─ Skills.checkForImprovement() ← extract reusable patterns
    │
    ▼
Assistant Response
```

#### Model Routing Strategy

```
┌─────────────────┐     ┌───────────────────────────────────────┐
│  Input Analysis  │     │           Model Selection             │
│                  │     │                                       │
│  "build an API"  ├────►│  coder  → Grok 4.20    ($2/MTok)    │
│  "what is X?"    ├────►│  fast   → Gemini Flash  ($0.08/MTok) │
│  "analyze this"  ├────►│  reason → Gemini Pro    ($1.25/MTok) │
│  "generate 100"  ├────►│  bulk   → MiniMax M2.7  ($0.08/MTok) │
│  "plan strategy" ├────►│  brain  → Claude Opus   ($15/MTok)   │
│  "hello"         ├────►│  general→ GPT-5.4       ($2.5/MTok)  │
└─────────────────┘     └───────────────────────────────────────┘
```

### `@lyrie/gateway` — The Channels

Multi-platform messaging gateway. Converts native platform messages to a unified format and routes them to the engine.

```
packages/gateway/
├── src/
│   ├── index.ts           # Gateway entry point
│   ├── common/
│   │   ├── types.ts       # UnifiedMessage, UnifiedResponse
│   │   └── router.ts      # MessageRouter + command dispatch
│   ├── telegram/
│   │   ├── bot.ts         # Zero-dependency Telegram client
│   │   ├── types.ts       # Telegram API types
│   │   ├── middleware.ts   # Rate limiting, auth, logging
│   │   └── handlers.ts    # /start, /help, /scan, /status
│   ├── discord/
│   │   └── bot.ts         # Discord bot skeleton
│   └── whatsapp/
│       └── bot.ts         # WhatsApp bot skeleton
```

#### Message Flow

```
Telegram Update
    │
    ├─ MiddlewarePipeline
    │   ├─ AuthChecker (user/chat allowlists)
    │   ├─ RateLimiter (per-user, per-minute)
    │   └─ RequestLogger
    │
    ├─ toUnified() ─── convert to UnifiedMessage
    │
    ├─ Command? ── yes ─► CommandHandler (e.g. /scan, /status)
    │             └─ no ─► MessageRouter → Engine.process()
    │
    └─ send() ─── convert UnifiedResponse back to Telegram
```

### `@lyrie/shield` — The Security Engine (Rust)

High-performance security scanning written in Rust. Called from the TypeScript ShieldManager via IPC or CLI.

```
packages/shield/
├── Cargo.toml
└── src/
    ├── lib.rs          # Library root
    ├── main.rs         # CLI entry point
    ├── scanner.rs      # File scanner (hash + signature matching)
    ├── malware.rs      # Malware pattern detection
    ├── behavioral.rs   # Behavioral analysis
    ├── rogue_ai.rs     # Rogue AI detection
    └── waf.rs          # Web Application Firewall
```

### `@lyrie/ui` — The Dashboard

Next.js 15 web dashboard for monitoring and managing the agent.

```
packages/ui/
├── src/
│   ├── app/
│   │   ├── page.tsx         # Home / overview
│   │   ├── layout.tsx       # Root layout
│   │   ├── overview/        # Dashboard overview
│   │   ├── agents/          # Agent management
│   │   ├── memory/          # Memory viewer
│   │   ├── shield/          # Shield status + threat logs
│   │   └── settings/        # Configuration
│   ├── components/          # Reusable UI components
│   └── lib/
│       └── utils.ts         # Utilities (cn, etc.)
```

## Memory Architecture

Lyrie uses a 5-layer memory system designed to prevent the corruption issues found in other agent platforms:

```
┌─────────────────────────────────────────────────────┐
│  Layer 4: Self-Healing                              │
│  Integrity checks, auto-recovery from archive       │
├─────────────────────────────────────────────────────┤
│  Layer 3: Live Working Memory                       │
│  Current session context, in-memory cache           │
├─────────────────────────────────────────────────────┤
│  Layer 2: Vector + Graph (planned)                  │
│  Semantic search, relationship tracking             │
├─────────────────────────────────────────────────────┤
│  Layer 1: Structured Core                           │
│  MASTER-MEMORY.md — human-readable, append-only     │
├─────────────────────────────────────────────────────┤
│  Layer 0: Immutable Archive                         │
│  Daily backups, never modified, disaster recovery   │
└─────────────────────────────────────────────────────┘
```

## Security Model

```
                    ┌──────────────────────┐
                    │    INPUT SCANNING     │
                    │                      │
                    │  Prompt injection     │
                    │  Social engineering   │
                    │  Dangerous commands   │
                    │  Credential exfil     │
                    └──────────┬───────────┘
                               │ clean
                    ┌──────────▼───────────┐
                    │   TOOL VALIDATION     │
                    │                      │
                    │  Path scoping        │
                    │  Command blocklist   │
                    │  Risk assessment     │
                    │  Sandbox enforcement │
                    └──────────┬───────────┘
                               │ approved
                    ┌──────────▼───────────┐
                    │  RUNTIME MONITORING   │
                    │                      │
                    │  Rogue AI detection  │
                    │  File system guard   │
                    │  Network monitoring  │
                    │  Behavioral analysis │
                    └──────────────────────┘
```

## Data Flow

```
.env
  │
  ▼
Config (Zod validated)
  │
  ├──► ShieldManager    ─── security rules loaded
  ├──► MemoryCore       ─── ~/.lyrie/memory/ created
  ├──► ModelRouter      ─── 9 models configured
  ├──► LyrieEngine      ─── tools + skills loaded
  └──► ChannelGateway   ─── channels started
         │
         ├── CLI (stdin/stdout)
         ├── Telegram (long polling)
         ├── Discord (WebSocket)
         └── WhatsApp (webhook)
```

## Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Runtime | Bun | 3x faster than Node, native TypeScript |
| Language | TypeScript | Type safety, developer experience |
| Security | Rust | Zero-cost abstractions, memory safety |
| Dashboard | Next.js 15 | React Server Components, App Router |
| Styling | Tailwind CSS 4 | Utility-first, zero runtime |
| Validation | Zod | Runtime type checking for config |
| Build | Turbo | Monorepo task orchestration |
| Testing | bun:test | Native, fast, zero config |

## Design Principles

1. **Security First** — Shield runs before anything else. Every input is scanned, every tool call is validated.
2. **Model Agnostic** — Lyrie routes tasks to the best model. Add providers without changing core logic.
3. **Self-Healing** — Memory corruption is detected and repaired automatically from immutable archives.
4. **Self-Improving** — Skills extracted from complex tasks become reusable patterns.
5. **Auditable** — <30K lines of code. Every line readable. No obfuscation.
6. **Zero External Dependencies** — Telegram bot uses raw `fetch`. No `telegraf`, no `grammy`.
7. **Migrate, Don't Lock** — Import data from 9 competing platforms. Your data is yours.

---

**© OTT Cybersecurity LLC** — [lyrie.ai](https://lyrie.ai)

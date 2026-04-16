# Getting Started with Lyrie Agent

Welcome to Lyrie Agent — the world's first autonomous AI agent with built-in cybersecurity.

## Prerequisites

- **[Bun](https://bun.sh)** v1.1+ (recommended) or Node.js v22+
- **[Rust](https://rustup.rs)** (for the Shield binary — optional, TypeScript fallback available)
- At least one AI provider API key (see below)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/lyrie-ai/lyrie-agent.git
cd lyrie-agent
```

### 2. Install Dependencies

```bash
bun install
```

### 3. Configure Environment

Copy the example environment file and add your API keys:

```bash
cp .env.example .env
```

Edit `.env` with your favorite editor:

```bash
# Required: at least one AI provider
ANTHROPIC_API_KEY=sk-ant-...      # Claude (Brain model)
OPENAI_API_KEY=sk-proj-...        # GPT-5.4 (General)
GOOGLE_API_KEY=AIza...            # Gemini (Fast + Reasoning)
XAI_API_KEY=xai-...              # Grok (Coder)
MINIMAX_API_KEY=...              # MiniMax (Bulk, cheapest)

# Optional: Local models via Ollama
OLLAMA_BASE_URL=http://localhost:11434
LYRIE_PREFER_LOCAL=true          # Use local models when available
```

> **Tip:** You only need ONE provider to get started. Lyrie routes tasks to the best available model automatically.

### 4. Build the Shield (Optional)

The Rust-based Shield provides faster threat scanning:

```bash
bun run shield:build
```

If you skip this step, the TypeScript Shield fallback is used automatically.

## Running Lyrie

### Quick Start (Core Only)

```bash
bun run start
```

This boots the engine with CLI-only mode. Type messages at the `lyrie>` prompt.

### Full Stack (Core + Gateway)

```bash
bun run scripts/start-all.ts
```

This boots the engine, memory, shield, model router, and channel gateway together.

### Development Mode (Watch)

```bash
bun run dev
```

Restarts automatically when you edit source files.

## Connecting Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather) on Telegram
2. Copy the bot token
3. Add to `.env`:

```bash
LYRIE_TELEGRAM_TOKEN=123456:ABC-DEF...

# Optional: restrict who can use the bot
LYRIE_TELEGRAM_USERS=123456789,987654321
LYRIE_TELEGRAM_CHATS=-1001234567890
LYRIE_TELEGRAM_RATE=30  # messages per user per minute
```

4. Start the gateway:

```bash
bun run scripts/start-all.ts
```

5. Send `/start` to your bot. You should see the Lyrie welcome screen with inline buttons.

### Available Telegram Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome screen with quick actions |
| `/help` | List all commands |
| `/status` | Agent & shield status |
| `/scan <url>` | Scan a URL for threats |
| `/protect` | Enable device protection |
| `/model` | View/switch AI models |

## Connecting Discord

1. Create a bot at [Discord Developer Portal](https://discord.com/developers/applications)
2. Add to `.env`:

```bash
LYRIE_DISCORD_TOKEN=your-bot-token
LYRIE_DISCORD_APP_ID=your-app-id
```

3. Start the gateway — Discord connects automatically.

## Connecting WhatsApp

1. Set up [WhatsApp Business API](https://business.whatsapp.com/products/business-platform)
2. Add to `.env`:

```bash
LYRIE_WHATSAPP_PHONE_ID=your-phone-number-id
LYRIE_WHATSAPP_TOKEN=your-access-token
```

## Running Tests

```bash
# All tests
bun test

# Core tests only
cd packages/core && bun test

# With coverage
bun test --coverage
```

## Migrating from Other Platforms

Lyrie can import your existing agent data:

```bash
# Auto-detect installed platforms
bun run migrate:detect

# Migrate from a specific platform
bun run migrate:openclaw
bun run migrate:hermes

# Migrate from everything
bun run migrate:all

# Preview without writing
bun run scripts/migrate.ts --from openclaw --dry-run
```

Supported platforms: OpenClaw, Hermes Agent, AutoGPT, NanoClaw, ZeroClaw, Dify, SuperAGI, Nanobot, grip-ai.

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `LYRIE_MODE` | `hybrid` | `cloud`, `local`, or `hybrid` |
| `LYRIE_PREFER_LOCAL` | `false` | Prefer local models when available |
| `LYRIE_MEMORY_PATH` | `~/.lyrie/memory` | Memory storage location |
| `LYRIE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LYRIE_SHIELD_MODE` | `active` | `passive` (log only), `active` (block threats), `strict` (block suspicious) |
| `NODE_ENV` | `development` | `development`, `production`, `test` |

## Project Structure

```
lyrie-agent/
├── packages/
│   ├── core/          # Engine, memory, shield, model router
│   ├── gateway/       # Telegram, Discord, WhatsApp bots
│   ├── ui/            # Next.js dashboard
│   └── shield/        # Rust security engine
├── scripts/           # CLI tools (migrate, start-all)
├── docs/              # Documentation
└── .github/           # Issue templates, CI
```

See [architecture.md](./architecture.md) for detailed system design.

## Troubleshooting

### "No AI providers configured"

Set at least one API key in `.env`. Or set `LYRIE_PREFER_LOCAL=true` and ensure Ollama is running.

### Telegram bot not responding

- Check the token is correct
- Ensure no other bot instance is polling (409 Conflict error)
- Check firewall allows outbound HTTPS to `api.telegram.org`

### Memory corruption

Lyrie's self-healing memory recovers automatically from archive backups. If issues persist:

```bash
# View memory status
ls -la ~/.lyrie/memory/master/
ls -la ~/.lyrie/memory/archive/

# Manual restore from most recent backup
cp ~/.lyrie/memory/archive/backup-YYYY-MM-DD.md ~/.lyrie/memory/master/MASTER-MEMORY.md
```

## Next Steps

- Read [Architecture](./architecture.md) to understand the 4-layer design
- Read [Contributing](./contributing.md) to help improve Lyrie
- Visit [lyrie.ai](https://lyrie.ai) for the full platform
- Star the repo ⭐ — it means a lot

---

**© OTT Cybersecurity LLC** — Built with 🛡️ by the team behind [Lyrie.ai](https://lyrie.ai)

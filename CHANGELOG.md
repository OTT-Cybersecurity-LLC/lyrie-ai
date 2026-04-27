# Changelog

All notable changes to Lyrie Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 1 (Core Agent Absorption — part 2: Memory + Shield Doctrine)
- **`ShieldGuard` cross-cutting Shield contract** (`packages/core/src/engine/shield-guard.ts`).
  Lightweight, dependency-free `scanRecalled` / `scanInbound` interface used by
  every layer that touches untrusted text. Built-in heuristic fallback so
  Lyrie ships with a Shield on EVERY surface, even the admin CLIs.
- **FTS5 cross-session memory search** (`packages/core/src/memory/fts-search.ts`).
  Adds `MemoryCore.searchAcrossSessions(query, opts)` and
  `MemoryCore.summarizeSession(opts)`. Hermes-inspired ranked recall with
  bm25, snippet highlights, and triggers that keep the FTS index in sync.
  Falls back to LIKE when FTS5 isn't available so memory recall keeps working
  in any SQLite build.
- **Shield wired through every Phase-1 layer**:
  - `MemoryCore.searchAcrossSessions` → `scanRecalled` on every snippet, redacts
    prompt-injection / credential-like material before it reaches the agent.
  - `DmPairingManager.greet` → `scanInbound` on first-touch DM body; abusers
    are refused without ever issuing a pairing code.
  - `McpRegistry.call` → `shieldFilter` on every text/resource block returned
    by third-party MCP servers.
- **Schema bump v1 → v2**: additive FTS5 virtual table + triggers. Existing
  databases are migrated idempotently on first boot. No destructive change.
- **`docs/shield-doctrine.md`**: the engineering rule — every layer of Lyrie
  has a Shield hook. New PRs that add untrusted-text surfaces without a
  Shield call are incomplete.
- **Unit tests**: 9 ShieldGuard, 9 FTS, 2 pairing-shield, 5 MCP-shield. All pass.

### Added — Phase 1 (Core Agent Absorption — part 1)
- **DM pairing policy** (`packages/gateway/src/security/dm-pairing.ts`) inspired by
  OpenClaw `dmPolicy="pairing"`. Three modes: `open` (back-compat default),
  `pairing` (unknown DMs receive a one-time code; operator approves), `closed`
  (allowlist only). Wire-in is additive — existing channel configs without
  `dmPolicy` keep working unchanged.
- **`lyrie pairing` operator CLI** (`scripts/pairing.ts`): `list`,
  `approve <channel> <code>`, `revoke <channel> <senderId>`. JSON store at
  `~/.lyrie/pairing.json` (mode 0600).
- **Channel config additions**: `dmPolicy` and (where missing) `allowedUsers`
  on `TelegramConfig`, `WhatsAppConfig`, `DiscordConfig`. Env vars added:
  `LYRIE_TELEGRAM_DM_POLICY`, `LYRIE_WHATSAPP_DM_POLICY`,
  `LYRIE_DISCORD_DM_POLICY`, `LYRIE_WHATSAPP_USERS`, `LYRIE_DISCORD_USERS`.
- **`@lyrie/mcp` package** — Model Context Protocol adapter. Client mode
  (stdio + http/sse), `McpRegistry` for `~/.lyrie/mcp.json` configs, and a
  `lyrie mcp list|call` CLI. Wire-protocol-compliant subset focused on
  interoperability with Claude Code, Cursor, Continue, Cline, Codex, Gemini
  CLI, and any other MCP-aware host.
- **Unit tests** for both: `dm-pairing.test.ts` (12 cases) and
  `registry.test.ts` (5 cases). All pass under `bun test`.

### Added — Phase 0 (Repo & Distribution Upgrades)
- **`lyrie doctor` command** — self-diagnostic for environment, dependencies, channel config, security policy, and update status.
- **GitHub Actions CI** matrix (Node 20/22/24 × Ubuntu/macOS) with Bun + Rust Shield build.
- **CodeQL security analysis** workflow (push/PR + weekly cron).
- **Nightly snapshot tagging** workflow.
- **Multi-platform release** workflow producing tarballs/zips for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and `x86_64-pc-windows-msvc`.
- **Dependabot** (npm, cargo, github-actions).
- **Pre-commit config** (whitespace, YAML/JSON/TOML lint, gitleaks secret scan, codespell).
- **Windows installer** at `scripts/install.ps1` (`irm | iex` parity with Claude Code).
- **CODE_OF_CONDUCT.md**, **CHANGELOG.md**, **CITATION.cff** files.
- **`.npmignore`** for clean npm publishes.
- **Release notes generator script** (`scripts/release/notes.sh`).
- **Localized README stubs** for `es`, `fr`, `de`, `zh-CN`, `ja`, `ar`, `pt-BR` in `locales/` (pointer files; full translations to follow in Phase 4).
- **Smithery + ClawHub skill listing pointers** in README footer.

### Changed
- Nothing. All Phase 0 changes are additive.

### Deprecated
- Nothing.

### Removed
- Nothing.

### Fixed
- Nothing.

### Security
- Phase 0 adds gitleaks pre-commit hook and CodeQL weekly scans of the JS/TS surface.

---

_Releases prior to v0.1.1 are documented in git history. Phase 0 lands as a single PR
on `feat/phase-0-upgrades` and will ship as `v0.1.1` once merged._

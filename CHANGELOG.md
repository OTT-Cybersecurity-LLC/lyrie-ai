# Changelog

All notable changes to Lyrie Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 2 (Pentest Absorption — part 1: GitHub Action)
- **`overthetopseo/lyrie-agent/action@v1`** — first-class GitHub Action
  for AI-powered pentest with Shield-on-PR.
  - Composite action (`action/action.yml`) with 12 inputs and 5 outputs.
  - Diff-scope by default: scans only PR-changed files.
  - Fail-on threshold (`critical` / `high` / `medium` / `low` / `none`).
  - SARIF upload to GitHub Code Scanning.
  - Single-comment-per-PR Markdown summary (updates in place, no spam).
  - Workflow artifact upload + GitHub job summary.
  - Shield Doctrine: target input passes `scanInbound` before any work.
- **Built-in ignore globs**: build artifacts (`.next/`, `dist/`, `target/`),
  vendor trees (`node_modules/`), Shield self-tests (those legitimately
  use injection patterns to verify Shield works).
- **`lyrie-shield: ignore-file` annotation** for legitimate security-content
  fixtures (UI strings naming attack types, documentation that quotes
  injection payloads, etc).
- **Self-test workflow** (`.github/workflows/action-selftest.yml`): the
  Lyrie Action runs against the Lyrie repo itself on every PR.
- **Tests**: 8 unit tests for the runner's Markdown + SARIF helpers.
  All pass.

### Fixed — Test Modernization (zero-fail suite)
- **All 36 pre-existing test failures resolved.** Tests had been written
  against an older API (string-shaped `execute()` returns, file-based
  `MASTER-MEMORY.md`, stale skill IDs). Modernized them to match the
  current production contract.
- **Real Shield upgrade**: `ShieldManager.scanInput` now also scans for
  dangerous shell patterns (`rm -rf /`, fork bombs, etc.) embedded in
  user input. Previously these were only caught at the tool-call boundary.
  Catches social-engineering attempts at the input layer.
- **Real ModelRouter upgrade**: removed the `// TEMPORARY: Route
  everything to brain` override that had been live since v0.1.0. Smart
  routing restored: coder / fast / reasoning / bulk / brain / general
  patterns. Adds a new `brain` pattern for strategy / planning / design.
- **SkillManager built-ins aligned** with the actual `skills/` workspace
  folder names: now ships `web-search`, `threat-scan`,
  `vulnerability-check`, `device-protect`, `code-execution`,
  `file-management`, `system-monitor` (renamed from the stale
  `code-writer` / `file-manager` / `threat-scanner`). 7 built-in skills
  total, all matching their workspace counterparts.
- **MemoryCore.status** now mentions "self-healing" so the operator's
  status string reflects the system's actual capability.
- **Test files modernized**: `tool-executor.test.ts`,
  `shield-manager.test.ts`, `model-router.test.ts`,
  `skill-manager.test.ts`, `memory-core.test.ts`. All now pass.
- **Net result**: **135 pass / 0 fail / 414 expectations** — the
  cleanest the suite has been since v0.1.0.

### Added — Phase 1 (Core Agent Absorption — part 4: Diff-View Edits)
- **`EditEngine`** (`packages/core/src/edits/edit-engine.ts`) — Cline-style
  diff-view file edits with approval gates. Targeted `oldText → newText`
  replacements with strict uniqueness checks, unified-diff generation
  (LCS-based, context-3 hunks), and three approval modes:
  `auto-approve`, `require-approval` (default — production-safe),
  `dry-run`.
- **Shield Doctrine on patches**: every plan's resulting content is
  scanned through `scanRecalled` BEFORE the file is touched. Blocked
  patches never land on disk (the doctrine table now shows ✅ for
  diff-view edits).
- **Edit ledger** at `~/.lyrie/edits.json` (mode 0600). Tracks pending
  plans + applied edits with sha256 before/after hashes; refuses to apply
  if the file drifted between plan and apply.
- **Workspace scoping**: paths outside the configured workspace root are
  refused.
- **`apply_diff` tool** registered in `ToolExecutor`. The agent uses this
  for in-place edits; `write_file` is preserved for whole-file writes.
  In `require-approval` mode, the tool returns the unified diff with a
  pending-approval pointer instead of applying.
- **`lyrie edits` operator CLI** (`scripts/edits.ts`):
  `list`, `review <planId>`, `approve <planId>`, `log`.
- **Unit tests (14 new, all pass)**: diff rendering, plan applicability,
  Shield-block-on-injection, Shield-block-on-credentials, auto-approve,
  drift detection, require-approval flow, dry-run, workspace scoping.

### Added — Phase 1 (Core Agent Absorption — part 3: Shield Doctrine Backfill)
- **Tool Executor Shield filter**: new `Tool.untrustedOutput` flag.
  Tools opting in have their successful output scanned through `ShieldGuard.scanRecalled`
  post-execute and unsafe content is redacted with a clear Shield notice + metadata flags.
  Default Built-in tools tagged `untrustedOutput: true`:
  `exec` (shell stdout), `read_file` (file contents), `web_search` (third-party snippets),
  `web_fetch` (scraped web content). Trusted tools (`write_file`, `list_directory`,
  `threat_scan`) intentionally pass through.
- **`ToolExecutor.setOutputShield(guard)`** to inject a real ShieldManager-backed guard.
- **Skill Manager Shield filter**: every successful skill output passes through the
  Shield before reaching the agent. Skills frequently shell out / scrape / call APIs —
  exactly the surfaces where prompt-injection appears. Failed-call output stays raw
  for operator debugging visibility.
- **`SkillManager.setOutputShield(guard)`** for the same injection pattern.
- **`docs/shield-doctrine.md` updated**: 5 layers now ✅, 3 layers tracked as planned.
- **Unit tests (10 new)**:
  - `tool-shield.test.ts` (5): redacts injection, redacts credentials, leaves benign
    alone, doesn't scan trusted tools, doesn't scan failed calls.
  - `skill-shield.test.ts` (5): same coverage for skills + non-string output handling.
  All pass.

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

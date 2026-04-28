# Changelog

All notable changes to Lyrie Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 3 (Distribution — part 4: Pluggable execution backends)
- **Lyrie execution-backend abstraction** (`packages/core/src/backends/`).
  Pluggable runner for Lyrie scans — same Shield Doctrine, same SARIF,
  different host.
- **`Backend` interface** (`backends/types.ts`):
    `kind: BackendKind`, `displayName`, `isConfigured()`,
    `preflight() → { ok, reason }`, `run(BackendRunRequest) → BackendRunResult`,
    optional `cleanup()`.
- **3 implementations:**
    - **`LocalBackend`** — default; runs on the caller. Always configured.
      Honors `LYRIE_LOCAL_DRY_RUN=1` for tests.
    - **`DaytonaBackend`** — spins up a Daytona devbox from
      `ghcr.io/overthetopseo/lyrie-agent:latest` (overridable), runs Lyrie
      inside, fetches SARIF from `/workspaces/{id}/files/lyrie-runs/lyrie.sarif`,
      tears down (TTL safety net at 1800s default). Full `BackendRunRequest`
      → create-workspace JSON translation. Injectable `FetchFn` so tests can
      drive the whole state machine without network.
    - **`ModalBackend`** — invokes a Modal serverless function
      (`POST /v1/functions/invoke`) with the same payload, surfaces
      `costUsd` when reported. Same `FetchFn` injection.
- **`getBackend()` factory** (`backends/factory.ts`) — resolves backend
  from explicit kind → `LYRIE_BACKEND` env → default "local". Reads each
  backend's required env vars (`DAYTONA_API_*`, `MODAL_TOKEN_*`,
  `LYRIE_*_REGION`, `LYRIE_*_IMAGE`, etc.). Throws on explicit kind/config
  mismatch.
- **`extractSarifSummary()`** — lenient SARIF → `{ highest, findingCount }`
  helper used by Daytona + Modal result paths.
- **`emptySarif()`** — minimal valid SARIF 2.1.0 doc for happy-path
  fallbacks.
- **`lyrie backend` CLI** (`scripts/backend.ts`):
    `bun run backend list                                # 3 backends, configured/unconfigured`
    `bun run backend status                              # resolved kind + per-backend status`
    `bun run backend show <local|daytona|modal>          # env-detected config`
    `bun run backend preflight [<kind>]                  # cheap auth/connectivity`
    `bun run backend run --kind=<k> --target=<dir> ...   # one-shot scan`
- **Core exports** (`packages/core/src/index.ts`) — 14 new exports:
    `LocalBackend`, `DaytonaBackend`, `ModalBackend`, `getBackend`,
    `lyrieEmptySarif`, `lyrieExtractSarifSummary`, `lyrieDescribeBackend`,
    `lyrieResolveBackendKind`, `lyrieReadDaytonaConfig`, `lyrieReadModalConfig`,
    `lyrieReadLocalConfig`, `LYRIE_SUPPORTED_BACKENDS`, plus full type
    surface (`Backend`, `BackendKind`, `BackendRunRequest`,
    `BackendRunResult`, `BackendResourceHints`, `LocalBackendConfig`,
    `DaytonaBackendConfig`, `ModalBackendConfig`, `AnyBackendConfig`,
    `BackendFactoryOptions`, `LyrieBackendFetchFn`).
- **Deployment recipes** (`deploy/`):
    - `deploy/modal/lyrie_modal.py` — ready-to-deploy Modal app,
      `modal deploy deploy/modal/lyrie_modal.py`.
    - `deploy/daytona/lyrie.devcontainer.json` — devcontainer spec for
      Daytona-hosted dev environments.
    - `deploy/README.md` — backend-by-backend deployment recipe.
- **README:** new "☁️ Where Lyrie runs" section + cross-link to `deploy/`.
- **Tests (33 new)** in `packages/core/src/backends/backends.test.ts`:
    `resolveBackendKind` (5), `extractSarifSummary` (3), env readers (3),
    `LocalBackend` (4 incl. dryRun), `DaytonaBackend` (8 incl. full state
    machine + cleanup verification + error fallthrough),
    `ModalBackend` (5 incl. cost surfacing), `getBackend` factory (5
    incl. mismatch error + describe). All pass.

Total Lyrie suite: **379 / 0 / 1544** TS + 63 Py = **442 / 0**
(was 346 / 0 / 1470 + 63 Py = 409 / 0).

### Added — Phase 3 (Distribution — part 3: Multi-channel gateway expansion)
- **7 new channel adapters** join Telegram + WhatsApp + Discord:
  - **Slack** (`packages/gateway/src/slack/bot.ts`) — Events API + Socket
    Mode normalization, Block Kit rendering for inline buttons,
    `block_actions` interaction handling.
  - **Matrix** (`packages/gateway/src/matrix/bot.ts`) — federated /sync
    pattern, `m.room.message` ingest, HTML formatting, `m.in_reply_to`
    threading, optional E2EE-ready device id.
  - **Mattermost** (`packages/gateway/src/mattermost/bot.ts`) — WebSocket
    v4 `posted` event ingest, `file_id` media, interactive props for
    buttons.
  - **IRC** (`packages/gateway/src/irc/bot.ts`) — RFC 2812 PRIVMSG
    ingest, DM vs channel detection, IRCv3 server-time honored,
    UTF-8-safe ~410-byte line splitting, bracketed `[text](url)` button
    rendering (no native buttons in IRC).
  - **Feishu / Lark** (`packages/gateway/src/feishu/bot.ts`) — single
    adapter for both 飞书 (mainland) and Lark (international) via
    `isLark` flag and `apiHost()` switch; `im.message.receive_v1`
    envelope ingest, verification-token gate, text + interactive
    (card) message rendering, tenant_access_token slot.
  - **Rocket.Chat** (`packages/gateway/src/rocketchat/bot.ts`) — DDP /
    REST pattern, system-message + self-loop filtering,
    `attachments.actions` interactive button rendering.
  - **WebChat** (`packages/gateway/src/webchat/bot.ts`) — the widget
    Lyrie owns end-to-end. WebSocket frame schema, callback frames,
    socket registration / drop, origin allow-list with wildcard
    subdomain support (`*.lyrie.ai`).
- **`ChannelType`** union extended (back-compat): `slack | matrix |
  mattermost | irc | feishu | rocketchat | webchat`.
- **Per-channel config interfaces** + full env-var wiring in
  `packages/gateway/src/index.ts`:
    `LYRIE_SLACK_BOT_TOKEN`, `LYRIE_MATRIX_*`, `LYRIE_MATTERMOST_*`,
    `LYRIE_IRC_*`, `LYRIE_FEISHU_*`, `LYRIE_ROCKETCHAT_*`,
    `LYRIE_WEBCHAT_*`.
- **`tryStart()` helper** for uniform start + dmPolicy wiring across
  all 7 new bots.
- **All 7 bots exported** alongside Telegram/WhatsApp/Discord from the
  gateway entry point.
- **README:** new "Where Lyrie talks to you" channel matrix table.
- **Tests (66 new)**: 7–9 unit tests per adapter — envelope
  normalization, self-loop filtering, media handling, button rendering,
  start() bailouts on missing secrets, ingest → handler dispatch loop,
  channel-specific quirks (IRC line splitting, WebChat origin
  allow-list with wildcard subdomain support, Feishu verificationToken
  gate, Matrix HTML formatting, Mattermost props.attachments,
  Rocket.Chat $date timestamp shape, etc.). All pass.

Total Lyrie suite: **346 / 0 / 1470** TS + 63 Py = **409 / 0**
(was 293 / 0 / 1349 + 63 Py = 356 / 0).

### Added — Phase 3 (Distribution — part 2: Lyrie Tools Catalog + cross-CI templates) [v0.3.1]
- **Lyrie Tools Catalog** (`packages/core/src/tools-catalog/`) — vetted
  registry of external security tools the agent can drive.
- **19 categories · 35 vetted tools · Lyrie-original recommend() engine.**
- **`lyrie tools` CLI** — list / categories / search / tag / recommend /
  status / show.
- **24 catalog tests** + 269 → 293 TS test count.
- **Cross-CI templates** (`action/templates/`) — GitLab CI / Jenkins /
  CircleCI drop-ins. Same Lyrie scan, same SARIF, every host.
- **README:** "No Docker. No yak-shaving." tagline + cross-CI pointer.
- **Action runner:** `__pycache__/`, `*.pyc`, `*.pyo` added to ignore
  globs.

### Added — Phase 3 (Distribution — part 1: Lyrie Python SDK)
- **Lyrie Agent Python SDK** (`sdk/python/`) — `pip install lyrie-agent`.
  Pure-Python port of every Lyrie pentest primitive, fully usable from
  any Python project. Zero runtime dependencies (httpx is opt-in via
  `lyrie-agent[http]`).
- **Eight modules ported with full parity:**
    - `lyrie.Shield` — Shield Doctrine. `scan_recalled` / `scan_inbound`.
    - `lyrie.AttackSurfaceMapper` — entry points, trust boundaries, tainted
      data flows, dependencies, hotspots. Same detector matrix as the TS
      mapper. `MAPPER_VERSION = lyrie-asm-py-1.0.0`.
    - `lyrie.StagesValidator` — six gates: pattern-reality, reachability,
      code-path, final-call, PoC, remediation. Auto-curl PoCs for shell /
      SQL / XSS / SSRF / path-traversal. 8-category remediation summaries.
    - `lyrie.scan_files` — multi-language scanners (JS / TS / Python / Go /
      PHP / Ruby / C / C++) with the same `lyrie-<lang>-*` rule namespace.
    - `lyrie.HttpProxy` — capture + classify + 7 signal detectors.
    - `lyrie.EditEngine` — diff-view edits with approval gates,
      Shield-on-patch, sha256 drift detection, workspace scoping.
    - `lyrie.ThreatIntelClient` — KEV-aligned advisories from
      research.lyrie.ai. Network-optional, in-memory TTL cache.
    - `lyrie.run_oss_scan` — the OSS-Scan service engine.
- **`lyrie-py` CLI** (`python -m lyrie.cli`):
    `lyrie-py shield <text>`
    `lyrie-py understand --root <path>`
    `lyrie-py scan-files --root <path>`
    `lyrie-py validate-finding --severity high --evidence "..."`
    `lyrie-py intel [--offline]`
  All commands honor `--json` where structured output is useful.
- **GitHub Actions**:
    - `sdk-python-ci.yml` — pytest matrix on Python 3.10/3.11/3.12/3.13
      across Ubuntu + macOS + sdist/wheel build verification with twine.
    - `sdk-python-publish.yml` — trusted-publisher PyPI release on
      `sdk-py-v*.*.*` tags.
- **Tests (63 new)**:
    - `test_shield.py`        — 8 cases
    - `test_attack_surface.py` — 8 cases
    - `test_stages.py`         — 15 cases
    - `test_scanners.py`       — 15 cases
    - `test_proxy_and_misc.py` — 17 cases (proxy + edits + threat-intel + oss-scan)
  All pass on Python 3.12. Total Lyrie suite now: **332 / 0** (269 TS + 63 Py).
- **README updated** with PyPI badge, Python embed example, and 332-test count.

### Added — Phase 2 (Pentest — part 7 / FINAL: Deeper SARIF rule metadata)
- **SARIF 2.1.0 rule + result metadata enriched** (`action/runner-helpers.ts`).
  Lyrie's GitHub Code Scanning output now carries the metadata GitHub
  actually uses for its UI:
    - `tool.driver.organization = "OTT Cybersecurity LLC"`
    - `tool.driver.semanticVersion = "0.2.6"`
    - `runs[].properties.generatedBy = "Lyrie.ai by OTT Cybersecurity LLC"`
    - **Per-rule** `defaultConfiguration.level`, `properties.tags`
      (“security” + `lyrie:<source>` + cwe), `properties["security-severity"]`
      (0–10 float, drives GitHub’s severity sidebar), `properties["lyrie:source"]`
      (shield/mapper/scanner/validator/intel/proxy), `help.text` + `help.markdown`,
      `fullDescription`, and `relationships[]` linking to CWE entries.
    - **Per-result** `partialFingerprints.lyrieFingerprint` for stable cross-run
      dedup, `properties["security-severity"]`, `properties["lyrie:confidence"]`
      (parsed out of the Stages A–F line), `properties["lyrie:source"]`,
      and `message.markdown` carrying the Lyrie / OTT Cybersecurity LLC signature.
- **Lyrie source classifier** infers which Lyrie module produced each rule
  from the finding id prefix (`lyrie-shield-*` → shield, `lyrie-flow-*` →
  mapper, `lyrie-jsts/py/go/php/rb/cpp-*` → scanner, threat-intel-enriched
  descriptions → intel, otherwise → validator).
- **`lyrie-shield: ignore-file`** annotation added to
  `packages/core/src/pentest/proxy/proxy.ts` because the proxy module
  contains literal credential-shape strings inside its own detector —
  product code, not a vector.
- **Tests**: 10 new SARIF metadata cases (driver organization, rule tags,
  help.markdown signature, CWE relationships, result fingerprints,
  per-result security-severity, lyrie:source inference, message.markdown
  signature, lyrie:confidence parsing, empty-findings still emits
  metadata). All pass. Total suite now: 269 / 0 / 706 expect()s.
- **Phase 2 CLOSED.** Roadmap progresses to Phase 3 next — Lyrie Python SDK
  on PyPI (`pip install lyrie-agent`) for embedding Lyrie inside any Python
  project.

### Added — Phase 2 (Pentest — part 6: Lyrie HTTP Proxy)
- **Lyrie HTTP Proxy** (`packages/core/src/pentest/proxy/`).
  Lyrie's purpose-built request/response inspection layer for offensive
  testing. Captures every HTTP exchange in-memory, classifies it,
  detects security signals, and offers structured replay with mutators.
- **9 security-signal detectors**:
    - missing-security-header (CSP, HSTS, X-Content-Type-Options,
      X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy)
    - weak-cookie-flag (HttpOnly, Secure, SameSite)
    - open-cors (wildcard ACAO)
    - auth-token-in-url (token / api_key / access_token / etc. in query)
    - verbose-error (stack-trace-shaped 5xx bodies)
    - secret-in-response (PEM / AWS / api_key shapes)
    - graphql-introspection-enabled
    - secret-in-request (planned hook)
    - unsafe-redirect (planned hook)
- **9 HTTP-surface classifiers**: login, register, logout,
  password-reset, search, upload, download, graphql, rest-list,
  rest-item, websocket-handshake, static, api-other, unknown.
- **7 structured Mutators**: header-add / header-set / header-remove,
  param-set / param-fuzz, body-replace, method-swap, path-fuzz.
- **Allow / deny host enforcement** on every `send()` and `replay()`
  so an operator can't fat-finger a request against an unauthorised
  host. The proxy refuses by default if either list is configured.
- **Shield Doctrine on responses**: every response body passes
  `scanRecalled` before the agent sees it. Captured pages are
  attacker-controlled territory — Lyrie defends by default.
- **`lyrie proxy` CLI** (`scripts/proxy.ts`):
    `bun run proxy send <METHOD> <URL>`
    `bun run proxy scan <URL>`
    `bun run proxy headers <URL>`
  In-memory only; nothing persisted to disk.
- **Tests**: 25 new (surface classification on 4 corpora, 9 signal
  detectors, 6 mutator behaviours including immutability, the full
  send / replay / Shield-redact / allow-host / deny-host / clear /
  signals flow). All pass. Total suite now: 259 / 0 / 669 expect()s.

### Added — Phase 2 (Pentest — part 5: Lyrie Threat-Intel)
- **Lyrie Threat-Intel Client**
  (`packages/core/src/pentest/threat-intel/`).
  Lyrie's runtime that pulls KEV-aligned CVE advisories from
  `research.lyrie.ai` and attributes them to:
    - dependencies discovered by the Attack-Surface Mapper
    - findings produced by the Multi-Language Scanners
    - findings whose text references a CVE / Lyrie advisory slug
  Network-optional: when the feed is unreachable the client returns no
  matches and never throws — CI is never gated on intel availability.
  Pluggable fetcher for hermetic tests + offline mode for fully offline
  pipelines. Built-in TTL cache (1h default) so CI runs that scan many
  PRs in a day don't pummel the feed.
- **`enrichFindings()`**: bumps KEV-listed matches to `critical` and
  appends a Lyrie Threat-Intel badge with CVSS, KEV status, Lyrie
  Verdict, and a `research.lyrie.ai` link inline in every finding
  description.
- **Action runner integration**: every PR run now enriches findings
  through the Threat-Intel client before they reach the Stages A–F
  validator. Findings carrying KEV-listed CVEs surface as critical with
  a one-line operator-facing verdict.
- **`lyrie intel` CLI** (`scripts/intel.ts`):
    `bun run intel list` — list cached advisories
    `bun run intel refresh` — force-refresh feed
    `bun run intel lookup <CVE>` — single advisory deep-dive
    `bun run intel scan-deps` — match feed against package.json
  Honors `LYRIE_INTEL_OFFLINE=1` for fully offline runs.
- **Lyrie semver-ish version-range matcher** (`versionAffected`): zero
  external semver dependency in core; supports `<= < > >= = ^ ~ A - B`
  forms.
- **Tests**: 15 new (versionAffected ranges, offline + seed, fetcher
  hook with success / HTTP-error / throw paths, dependency matching
  including version filtering and scope-loose matching, CVE-text +
  slug-text finding matching, KEV severity bumping, no-match passthrough).
  All pass. Total suite now: 234 / 0 / 619 expect()s.

### Added — Phase 2 (Pentest — part 4: Multi-Language Scanners + Lyrie OSS-Scan)
- **Lyrie Multi-Language Vulnerability Scanners**
  (`packages/core/src/pentest/scanners/`).
  Eight Lyrie-original scanners with 53 detection rules:
    - `lyrie-jsts` (9 rules) — JavaScript / TypeScript: shell-injection,
      eval / Function constructor, innerHTML XSS, template-string SQL,
      SSRF via fetch, JWT alg=none, prototype pollution, hard-coded
      secrets, open redirect.
    - `lyrie-py` (9 rules) — Python: subprocess shell=True, os.system,
      pickle.loads, yaml.load, eval/exec, Jinja2 autoescape=False,
      f-string SQL, Flask debug=True, hard-coded credentials.
    - `lyrie-go` (6 rules) — Go: /bin/sh -c shell, fmt.Sprintf SQL,
      InsecureSkipVerify, filepath.Join + ../, hard-coded secrets, XXE.
    - `lyrie-php` (7 rules) — PHP: shell-exec family, eval, unserialize,
      $_GET/$_POST SQL, dynamic include LFI/RFI, XXE, hard-coded secrets.
    - `lyrie-rb` (6 rules) — Ruby: backticks/system/%x{}, YAML.load,
      Marshal.load, ActiveRecord interpolated where(), mass-assignment
      without permit(), hard-coded secrets.
    - `lyrie-cpp` (5 rules) — C/C++: strcpy/strcat/sprintf/gets, system,
      printf with non-literal format, use-after-free heuristic,
      rand() for cryptographic use.
  Each scanner emits the `Lyrie.ai by OTT Cybersecurity LLC` signature
  and a versioned `lyrie-<lang>-1.0.0` tag.
- **Action runner integration**: GitHub Action runs all eight scanners
  on every PR alongside the Shield baseline + Attack-Surface Mapper.
  Scanner findings flow through Stages A–F validation so only
  confirmed signals ship.
- **Lyrie OSS-Scan service** (`packages/core/src/pentest/oss-scan/service.ts`).
  Free public scan at `research.lyrie.ai/scan`. Submit any public repo URL
  (GitHub / GitLab / Bitbucket / Codeberg), get a full Lyrie report
  (Mapper + Scanners + Stages A–F + auto-PoC + remediation) in seconds.
  Hardened URL validation: shell-injection-shaped owner/repo refused,
  loopback + RFC1918 + link-local hosts blocked at the gate, malformed
  refs rejected, scheme allowlist (`http`/`https` only). Total scan
  bounded by file count + bytes-per-file + wall-clock timeout.
- **`lyrie scan` CLI** (`scripts/scan.ts`):
    `bun run scan <repoUrl> [--ref <branch>] [--json]`
  Operator wrapper around the OSS-Scan service.
- **Tests**: 43 new (29 multi-language scanners + 14 OSS-Scan service).
  All pass. Total suite now: 219 / 0.
- **README updated**: highlights Multi-Language Scanners + OSS-Scan,
  test badge bumped to 219, new CLI entry for `lyrie scan`.

### Added — Phase 2 (Pentest — part 3: Stages A–F Validator)
- **Lyrie Stages A–F Exploitation Validator**
  (`packages/core/src/pentest/stages-validator.ts`).
  Every raw finding from a scanner now passes through six validation gates
  before it can ship as confirmed:
    - **Stage A** — Pattern reality (filters comments, regex.exec false
      positives, parameterized SQL, textContent XSS sinks, etc.)
    - **Stage B** — Reachability (test/spec files filtered, trust-boundary
      lookup against the Attack-Surface Mapper, severity bumped on
      reachable+unprotected paths)
    - **Stage C** — Code-path existence (build artifacts, `node_modules`,
      `.next`, `dist`, `.min.js` filtered)
    - **Stage D** — Final call (rolls up A–C verdicts, promotes confidence
      when reachable+unprotected)
    - **Stage E** — PoC generation (auto-curl PoCs for shell-injection,
      sql-injection, xss, ssrf, path-traversal; falls back to
      `needs-human-poc` for unsupported categories)
    - **Stage F** — Remediation (concrete summary per category, optional
      `oldText→newText` patch wired through the EditEngine)
  Every validated finding carries the `Lyrie.ai by OTT Cybersecurity LLC`
  signature and a confidence score 0–1.
- **Action runner integration**: the GitHub Action now runs every finding
  through `validateBatch` and only ships confirmed signals. Reports
  include the Stages A–F verdict line + auto-generated PoCs in fenced
  code blocks + Lyrie remediation summaries.
- **`@lyrie/core` exports**: `validateFinding`, `validateBatch`,
  `STAGES_VALIDATOR_VERSION`, plus all stage / verdict / category types.
- **Tests (24 new for the validator)**: Stage A pattern-reality scenarios,
  Stage B reachability with surface lookup, Stage C build-artifact / test
  filtering, Stage E auto-PoC for each supported category, Stage F
  remediation coverage, batch filtering with and without observations,
  signature + version checks, confidence scoring bounds. All pass.
- **README rewritten** for current state — highlights the Shield Doctrine,
  Attack-Surface Mapper, Stages A–F validator, GitHub Action, MCP, FTS5
  memory, diff-view edits, DM pairing, doctor; includes the doctrine
  surface table, operator-CLI summary, and an updated test count
  (176 pass / 0 fail).

### Added — Phase 2 (Pentest — part 2: Attack-Surface Mapper + Lyrie-only branding)
- **Lyrie Attack-Surface Mapper** (`packages/core/src/pentest/attack-surface.ts`).
  Lyrie's purpose-built static security mapper. Before any vulnerability
  scanner runs, the mapper builds a structural picture of the target:
  entry points (HTTP routes, CLI commands, file readers, env consumers,
  deserialization sinks, subprocess spawns, websockets, cron), trust
  boundaries (auth gates, RBAC checks, rate limits, sandbox crossings,
  Shield gates), tainted data flows (e.g. user-message → shell,
  http-input → sql), full dependency catalogue across npm / cargo /
  pip / go / ruby, and ranked risk hotspots.
  Every emitted artifact carries the embedded signature
  `Lyrie.ai by OTT Cybersecurity LLC` and a `mapperVersion`.
- **`lyrie understand` CLI** (`scripts/understand.ts`): map any workspace
  with one command. JSON + human-readable output modes.
- **Action runner integration**: the GitHub Action now produces an
  attack-surface summary section in every PR report and promotes the
  highest-risk tainted flows (risk ≥ 7) into SARIF + PR-comment findings.
- **Lyrie-only branding pass**: stripped every external-product reference
  from source comments. Internal modules now name Lyrie's own components
  exclusively, with `Lyrie.ai by OTT Cybersecurity LLC` signatures across
  edit-engine, fts-search, dm-pairing, channels/gateway, mcp/README,
  action/README, ai-pentest skill, and shield-doctrine. Migration
  adapters and the README comparison table keep their factual
  competitor references (those are legitimate interop / positioning).
- **Tests (9 new for the mapper)**: HTTP-route detection, subprocess +
  file-reader detection, env-var detection, auth + Shield boundaries,
  rate-limit detection, taint flow risk scoring, npm dependency
  collection, hotspot ranking + signature, ignore-file annotation.
  All pass.

### Added — Phase 2 (Pentest — part 1: GitHub Action)
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

## [0.3.7] — 2026-04-28

### Added — npm package publication
- **lyrie-agent is now on npm** — `npm install lyrie-agent` works globally
- Fixed release CI pipeline: turbo build filter (skip Next.js UI package), npm provenance, 2FA bypass token
- Fixed `package.json` repository URL to match actual GitHub repo for sigstore provenance
- **npmjs.com/package/lyrie-agent** — 0 dependencies, MIT, 3.0 MB, 408 files


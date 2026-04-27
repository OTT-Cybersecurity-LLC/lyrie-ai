# 🛡️ The Lyrie Shield Doctrine

> **Cybersecurity isn't a plugin — it's Layer 1.**
>
> Every layer of Lyrie that touches untrusted text must pass that text through
> a Shield contract before it influences the agent. There are no exceptions,
> no "we'll add it later", no "internal only" carve-outs.

This document is the rule that governs **every PR** to the Lyrie repo.

## The contract

Lyrie ships two Shield surfaces:

1. **`ShieldManager`** — `packages/core/src/engine/shield-manager.ts`
   The full battery: tool-call validation, path scoping, command pattern
   blocking, event log, mode (`passive | active | strict`). Wired into the
   engine.

2. **`ShieldGuard`** — `packages/core/src/engine/shield-guard.ts`
   The cross-cutting contract every other module depends on. A small,
   dependency-free interface with two methods:
   ```ts
   interface ShieldGuardLike {
     scanRecalled(text: string): ShieldVerdict; // memory hits, MCP results
     scanInbound(text: string): ShieldVerdict;  // first DM, pairing, etc.
   }
   ```
   `ShieldManager` satisfies this interface natively. Modules that don't have
   a manager available use `ShieldGuard.fallback()` (built-in heuristic).

## The rule

For every Lyrie surface that handles **text not authored by the operator**:

| Layer | Hook | Why |
|---|---|---|
| **Channel inbound (DMs)** | `evaluateDmPolicy` (router) | First-line gate; pairing or allowlist before reaching the engine. |
| **Pairing greeting** | `DmPairingManager.greet` calls `scanInbound` | Pairing codes are a small attack surface; don't issue codes to obvious abusers. |
| **Memory recall** | `searchAcrossSessions` calls `scanRecalled` | Recalled snippets can carry prompt-injection. Redact, don't drop. |
| **MCP tool results** | `McpRegistry.shieldFilter` | Third-party MCP servers are untrusted. Scan every text/resource block. |
| **Tool output (untrustedOutput=true)** | `ToolExecutor.shieldFilterOutput` | Shell stdout, web fetch, web search, file reads are scanned post-execute. |
| **Skill output** | `SkillManager.shieldFilter` | Skills shell out, scrape, or call APIs — every output passes the Shield. |
| **Cross-session summaries** | summarizer runs on already-shielded inputs | Defense-in-depth. |
| **Browser content / scrapes** | _(via `web_fetch` `untrustedOutput`)_ — standalone browser package gets dedicated hook in Phase 2 | Web pages are the #1 prompt-injection vector. |
| **External webhooks** | _(planned: Phase 2)_ | All inbound webhooks must pass through `scanInbound`. |
| **Diff-view applied edits** | `EditEngine.plan` calls `scanRecalled` on patch contents | Patches are scanned BEFORE the file is touched; blocked patches never land on disk. |

If you add a new surface that touches untrusted text and it does **not**
appear in this table or call into one of the two Shield types, your PR is
incomplete. Add the hook, add a test, or write down explicitly why this
particular surface is exempt and get sign-off from the maintainers.

## Verdicts

```ts
{ blocked: false }                                   // pass through
{ blocked: true, severity: "high",      reason: "…" } // redact / refuse
{ blocked: true, severity: "critical",  reason: "…" } // refuse + log
```

`severity` levels:
- `none` / `low` — informational; never block alone
- `medium` — warn + redact when used as recalled content
- `high` — redact recalled, refuse inbound for credentials/exfil
- `critical` — refuse everywhere, log to operator stderr

## Tests

Every Shield-aware module ships with at least one test that asserts:

1. Benign content passes through (no false positive)
2. A known-bad pattern is blocked (no false negative)
3. The redaction shape is right (e.g. `⟦SHIELDED⟧` marker for memory hits)

Test files live next to their modules (`*.test.ts`).

## Why this matters

Every other agent in the field is naked. They ship a clever LLM loop and
hope nothing in their context window flips them. Lyrie is the agent that
**defends itself while it works** — the Shield is Lyrie's entire wedge.
If we lose the Shield, we lose the wedge.

So: every layer, every PR, every time.

— _Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai_

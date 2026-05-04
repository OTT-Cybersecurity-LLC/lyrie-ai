# Lyrie Brand Guide

## Product Name
- ✅ Lyrie
- ✅ Lyrie.ai
- ✅ LyrieAAV, LyrieShield, LyrieEvolve, Omega-Suite
- ❌ Never in user-facing text: OpenClaw, Claude, ChatGPT, AutoGPT

## Company Name
OTT Cybersecurity LLC (legal entity) / Lyrie.ai (product brand)

## Tagline
"The autonomous security agent."

## Mission
Building the security infrastructure of the AI era.

## What Lyrie Is
Offensive + Defensive + Research in one daemon.  
The Agent Trust Protocol is ours. We authored it.

---

## URL Standard
| Context | Correct URL |
|---|---|
| Homepage | https://lyrie.ai |
| Research posts | https://lyrie.ai/research/... |
| ATP spec | https://lyrie.ai/atp |
| ❌ Old subdomain | ~~research.lyrie.ai~~ → use lyrie.ai/research |

---

## API Provider Names (internal/technical only — not branding)

These appear in config and routing tables as technical identifiers. They are **never** used in marketing copy or user-facing strings.

| Identifier | What it is |
|---|---|
| `anthropic/claude-*` | Anthropic API provider |
| `openai/gpt-*` | OpenAI API provider |
| `google/gemini-*` | Google API provider |
| `nvidia/nim-*` | NVIDIA NIM inference |

Provider IDs in routing tables are technical — not brand claims.

---

## Migration Feature References (intentional — these are product features)

Lyrie supports migration from other platforms. These names appear as **feature names** in migration code and CLI commands:

```
lyrie migrate --from openclaw
lyrie migrate --from autogpt
lyrie migrate --from hermes
```

These are **migration sources**, not endorsements. They appear:
- In `packages/core/src/migrate/` — migration modules
- In `lyrie skills import --from openclaw` — skill import feature
- In CLI help text describing supported migration sources
- In the README comparison table (competitive analysis)

**Rule:** migration/compat references = KEEP. User-facing branding comparisons = always favor Lyrie.

---

## Copyright / Author Fields

Every source file and package should use:

```
© OTT Cybersecurity LLC — https://lyrie.ai
```

or the MIT footer:

```
Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
```

package.json author field:
```json
"author": "OTT Cybersecurity LLC <dev@lyrie.ai> (https://lyrie.ai)"
```

---

## Internal Code Comments

Source code comments should describe Lyrie's own capabilities and design decisions — not compare against competitors. Prefer:

- ✅ "Lyrie's advanced memory system with auto-categorization..."
- ✅ "Configurable timeouts — default 10s per operation"
- ❌ "Better than [Competitor]: ..."
- ❌ "Ported from [Competitor] v2.1.88..."
- ❌ "Inspired by [Competitor]..."

---

## Research / Threat Intelligence Attribution

```
Lyrie Threat Intelligence — lyrie.ai/research
```

Or on a single line:
```
PoC by Lyrie Threat Intelligence (lyrie.ai/research)
```

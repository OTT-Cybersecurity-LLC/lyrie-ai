# LyrieEvolve — Autonomous Self-Improvement

> Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai

LyrieEvolve is the self-improvement subsystem of Lyrie Agent (v0.5.0+). It records task outcomes, scores them, extracts reusable skill patterns, retrieves context for active tasks, and runs a Dream Cycle to prune stale patterns.

---

## Architecture

```
Outcomes (JSONL)
     │
     ├── Scorer          → task-outcome.jsonl
     ├── SkillExtractor  → skills/auto-generated/*.md
     ├── Contexture      → in-memory (future: LanceDB lyrie_contexture)
     └── Dream Cycle     → batch pipeline (score → extract → prune → report)
```

---

## Components

### 1. Scorer (`packages/core/src/evolve/scorer.ts`)

Records and scores task outcomes across 5 domains.

**Domains:** `cyber` | `seo` | `trading` | `code` | `general`

**Score values:**
- `0` — failed / rejected / harmful
- `0.5` — partial / ambiguous
- `1` — success / confirmed value

**Usage:**

```typescript
import { Scorer } from "@lyrie/core";

const scorer = new Scorer();
const outcome = scorer.score("task-123", {
  domain: "code",
  signals: { testsPass: true, buildSucceeds: true, prMerged: true },
}, "All CI checks passed, PR merged");
// outcome.score === 1
```

**Domain-specific signals:**

| Domain | Key Signals |
|--------|-------------|
| `cyber` | `confirmed`, `falsePositive`, `pocGenerated`, `patchApplied`, `shieldBlocked` |
| `seo` | `keywordsRanked`, `contentPublished`, `backlinksAcquired`, `issuesResolved` |
| `trading` | `profitable`, `pnlRatio`, `drawdownExceeded`, `riskRespected`, `signalAccuracy` |
| `code` | `testsPass`, `buildSucceeds`, `noLintErrors`, `prMerged`, `linesChanged` |
| `general` | `completed`, `userApproved`, `userRejected`, `retries` |

Outcomes are appended to `~/.lyrie/evolve/outcomes.jsonl`. Summaries are Shield-scanned before storage.

---

### 2. Skill Extractor (`packages/core/src/evolve/skill-extractor.ts`)

Reads `outcomes.jsonl`, finds high-quality sessions (score >= 0.5), and writes OpenClaw-compatible SKILL.md files.

**Features:**
- Groups outcomes by domain
- Injects an LLM call to extract 1-3 skill patterns (injectable `ExtractorLLM` interface)
- Built-in heuristic fallback (`HeuristicExtractorLLM`) — no LLM required
- Cosine dedup: skips patterns with similarity > 0.85 to existing skills
- Writes to `skills/auto-generated/`

**Usage:**

```typescript
import { SkillExtractor } from "@lyrie/core";

const extractor = new SkillExtractor({ minScore: 0.5 });
const result = await extractor.extract();
// result.written, result.skippedDuplicates
```

**CLI:**
```bash
bun run scripts/evolve.ts extract
```

---

### 3. Contexture Layer (`packages/core/src/evolve/contexture.ts`)

Retrieves relevant skill contexts for active tasks and builds prompt injections.

**Features:**
- In-memory store (LanceDB-ready: table name `lyrie_contexture`)
- Cosine similarity retrieval with `retrieve(query, domain?, topK=3)`
- **MMR (Maximal Marginal Relevance)** diversity — λ=0.7 by default
- `buildInjection(contexts)` → structured `<lyrie_context>` block for prompt injection
- Shield-scanned on store; auto-evicts lowest-score entries at capacity (1000)

**Usage:**

```typescript
import { Contexture } from "@lyrie/core";

const ctx = new Contexture();
ctx.store({ id: "s1", domain: "cyber", summary: "...", score: 1, ... });

const results = ctx.retrieve("XSS injection", "cyber", 3);
const injection = ctx.buildInjection(results);
// Prepend injection to system prompt
```

---

### 4. Dream Cycle (`packages/core/src/evolve/dream-cycle.ts`)

Batch pipeline that runs while Lyrie is idle (typically at 4AM Dream Cycle cron).

**Steps:**
1. Count unprocessed outcomes
2. Extract skills via SkillExtractor
3. Prune stale skills (avgScore < 0.3 after 5+ uses)
4. Return `DreamReport`

**CLI:**
```bash
# Full run
bun run scripts/dream-evolve.ts

# Preview without writes
bun run scripts/dream-evolve.ts --dry-run
```

---

## CLI Reference (`lyrie evolve`)

```bash
bun run scripts/evolve.ts <command>

Commands:
  status                   Show LyrieEvolve system status + version info
  extract                  Extract skills from high-quality outcomes
  dream [--dry-run]        Run the full Dream Cycle pipeline
  stats                    Outcome statistics by domain and score
  skills list              List auto-generated skill files
  skills show <id>         Show a specific skill file
  skills prune             Identify and remove stale skills
  train                    Export training batch (outcomes with score >= 0.5)

Options:
  --outcomes <path>        Override ~/.lyrie/evolve/outcomes.jsonl
  --skills-dir <path>      Override skills directory
  --dry-run                Preview without writing
```

---

## Python SDK

```python
from lyrie.evolve import LyrieEvolve

client = LyrieEvolve()

# Score a task
outcome = await client.score("task-123", "code", {
    "tests_pass": True,
    "build_succeeds": True,
})

# Retrieve context
contexts = await client.get_context("XSS vulnerability", domain="cyber", top_k=3)

# Extract skills
result = await client.extract_skills(dry_run=True)

# Training batch
batch = await client.get_training_batch(domain="code", min_score=0.5, limit=100)
```

---

## Storage Layout

```
~/.lyrie/evolve/
├── outcomes.jsonl      ← scored task outcomes (append-only)
└── skills/             ← auto-generated skill files (when using default skillsDir)

<repo>/skills/auto-generated/
└── auto-<domain>-<ts>.md  ← OpenClaw-compatible SKILL.md files
```

---

## Shield Integration

Every text that enters the Evolve system passes through the Shield Doctrine:
- Summaries are `scanRecalled()` before being written to outcomes.jsonl
- Stored contexts are `scanRecalled()` before entering the Contexture table
- Blocked content is silently dropped (no partial writes)

---

## Pruning Rules

A skill is a candidate for pruning when:
- `avgScore < 0.3` (consistently low quality)
- `useCount >= 5` (has been tried enough times to confirm it's not useful)

Both conditions must be true. New skills with fewer than 5 uses are never pruned.

---

_© OTT Cybersecurity LLC — https://lyrie.ai — MIT License_

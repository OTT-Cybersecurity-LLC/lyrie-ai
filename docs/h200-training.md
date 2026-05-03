# Training Lyrie's Own Model on the H200

> **Target:** H200 GPU node — `ssh -p 38084 root@210.157.233.86`
> **Method:** GRPO (Group Relative Policy Optimization) via [Atropos](https://github.com/NousResearch/atropos)
> **Base model:** `nous-hermes3-70b` (default; swap to any compatible HuggingFace model)

---

## Overview

The `LyrieEvolve` training pipeline converts high-quality task outcomes (scored in production)
into structured JSONL training data, uploads it to the H200, then runs GRPO fine-tuning to
produce a Lyrie-flavoured checkpoint.

```
outcomes.jsonl  →  TrainingExporter  →  training.jsonl  →  H200 GRPO  →  lyrie-model/
```

---

## Step 1 — Export training data

Export all outcomes with score ≥ 0.5 across all domains:

```bash
bun run scripts/evolve.ts train \
  --export atropos \
  --min-score 0.5 \
  --domains all \
  --out ./training.jsonl
```

Export cyber + code only (higher precision):

```bash
bun run scripts/evolve.ts train \
  --export atropos \
  --min-score 0.5 \
  --domains cyber,code \
  --out ./training.jsonl
```

Check how many samples are ready before exporting:

```bash
bun run scripts/evolve.ts train --status
```

Sample `--status` output:

```
🎓 LyrieEvolve Training Status

   Version:       lyrie-evolve-training-exporter-1.0.0
   Outcomes file: /Users/apollogroup/.lyrie/evolve/outcomes.jsonl
   Total samples: 3842
   Ready (≥0.5):  2910
   Last outcome:  2026-05-04T00:00:00.000Z

   Domain breakdown:
     cyber      1240 samples
     code        887 samples
     seo         512 samples
     trading     271 samples
```

---

## Step 2 — Upload to H200

```bash
scp training.jsonl root@210.157.233.86:~/lyrie-training/
```

If the directory doesn't exist yet:

```bash
ssh -p 38084 root@210.157.233.86 "mkdir -p ~/lyrie-training"
scp -P 38084 training.jsonl root@210.157.233.86:~/lyrie-training/
```

---

## Step 3 — Run GRPO training on H200

SSH in and run:

```bash
ssh -p 38084 root@210.157.233.86
```

Install Atropos (one-time):

```bash
pip install atropos
```

Run GRPO training:

```bash
atropos train \
  --data ~/lyrie-training/training.jsonl \
  --base-model nous-hermes3-70b \
  --lora-rank 64 \
  --reward-field reward \
  --output ~/lyrie-model/
```

### GRPO training flags explained

| Flag | Value | Notes |
|---|---|---|
| `--data` | `training.jsonl` | Atropos format JSONL |
| `--base-model` | `nous-hermes3-70b` | Any HuggingFace-compatible 70B |
| `--lora-rank` | `64` | LoRA rank; increase to 128 for full quality run |
| `--reward-field` | `reward` | Maps to Lyrie's `score` field (0, 0.5, 1) |
| `--output` | `~/lyrie-model/` | Checkpoint saved here |

**Estimated training time on H200:**
- 1000 samples, LoRA-64: ~12 min
- 5000 samples, LoRA-64: ~55 min
- 10000 samples, LoRA-128: ~3 hr

---

## Step 4 — Use your trained model

Point the Lyrie daemon at the local checkpoint:

```bash
lyrie daemon --provider local --model ~/lyrie-model/
```

Or in `~/.lyrie/config.json`:

```json
{
  "provider": "local",
  "model": "/root/lyrie-model/"
}
```

---

## Export format reference

### Atropos (GRPO) — default

Each line:

```json
{
  "messages": [
    {"role": "system", "content": "You are Lyrie, an autonomous cyber operations AI..."},
    {"role": "user", "content": "Task: XSS vulnerability confirmed with working PoC"},
    {"role": "assistant", "content": "Completed: XSS vulnerability confirmed with working PoC [score=1, domain=cyber]"}
  ],
  "reward": 1.0,
  "domain": "cyber",
  "task_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### OpenAI SFT

```bash
bun run scripts/evolve.ts train --export openai-sft --out ./finetune.jsonl
```

Produces OpenAI fine-tuning JSONL compatible with `openai api fine_tunes.create`.

### ShareGPT

```bash
bun run scripts/evolve.ts train --export sharegpt --out ./sharegpt.jsonl
```

Uses `from: human/gpt/system` conversation format.

---

## Domain system prompts

Each domain gets a tailored system prompt injected into training records:

| Domain | System prompt focus |
|---|---|
| `cyber` | Vulnerability assessment, threat hunting, Shield doctrine |
| `seo` | Rankings, content, backlinks, technical audits |
| `trading` | Signal accuracy, risk management, drawdown limits |
| `code` | Correctness, security, minimal changes |
| `general` | Accurate completion, low retries |

---

## Reward signal

Lyrie's `score` field maps directly to GRPO reward:

| Score | Meaning | GRPO signal |
|---|---|---|
| `0` | Failed / rejected / false positive | Negative |
| `0.5` | Partial / ambiguous | Neutral |
| `1` | Confirmed success | Positive |

The GRPO optimizer amplifies behaviours rewarded with `1.0` and suppresses those scored `0`.

---

## Running more Dream Cycles to build more data

The more outcomes stored, the richer the training set. To generate more outcomes:

1. Run Lyrie in production — every task outcome is scored and appended to `outcomes.jsonl`.
2. Periodically run the Dream Cycle to extract skill patterns:

   ```bash
   bun run scripts/evolve.ts dream
   ```

3. Check training readiness:

   ```bash
   bun run scripts/evolve.ts train --status
   ```

4. Re-export and retrain when you have significantly more samples.

---

*Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai*

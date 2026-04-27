# 🛡️ Lyrie Pentest Action

Run Lyrie's autonomous AI pentest in your GitHub Actions pipeline.
Finds vulnerabilities, validates findings with Lyrie Shield, posts a
Markdown summary on every pull request, and uploads SARIF to GitHub
Code Scanning.

> **Phase 2 starter (v0.2.x)** — wraps the existing
> [`skills/ai-pentest/`](../skills/ai-pentest/) engine and Lyrie Shield.
> Deeper RAPTOR-style attack-surface mapping and Stages A–F validation
> land in the next two PRs.

## Usage

```yaml
name: Lyrie Pentest
on:
  pull_request:
  push:
    branches: [main]

jobs:
  lyrie:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # for PR comments
      security-events: write # for SARIF upload
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # required for diff-scope

      - uses: overthetopseo/lyrie-agent/action@v1
        with:
          scan-mode: quick
          scope: diff
          fail-on: high
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `target` | `./` | Target URL or path. |
| `scan-mode` | `quick` | `quick` / `full` / `recon` / `vulnscan` / `apiscan`. |
| `scope` | `diff` | `full` (entire target) or `diff` (PR-changed files). |
| `diff-base` | `origin/main` | Base ref for diff scope. |
| `fail-on` | `high` | Severity that fails the build: `critical` / `high` / `medium` / `low` / `none`. |
| `anthropic-api-key` | — | Claude API key. |
| `openai-api-key` | — | OpenAI fallback. |
| `brave-api-key` | — | Brave Search OSINT. |
| `shield-mode` | `active` | Lyrie Shield mode: `passive` / `active` / `strict`. |
| `output-dir` | `lyrie-runs` | Directory for report artifacts. |
| `upload-sarif` | `true` | Upload SARIF to GitHub Code Scanning. |
| `comment-on-pr` | `true` | Post Markdown summary as a PR comment. |
| `github-token` | `${{ github.token }}` | Token for PR comments + SARIF upload. |

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Total findings. |
| `critical-count` | Critical-severity count. |
| `high-count` | High-severity count. |
| `report-path` | Path to the Markdown report. |
| `sarif-path` | Path to the SARIF file. |

## Permissions

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

## What you get

1. **Markdown report** at `lyrie-runs/report.md` (uploaded as workflow artifact).
2. **JSON output** at `lyrie-runs/report.json` for downstream tooling.
3. **SARIF** at `lyrie-runs/lyrie.sarif`, auto-uploaded to GitHub Code Scanning.
4. **Single PR comment** that updates in place on every push (no duplicate
   comment spam).
5. **Job summary** rendered into the GitHub Actions step summary tab.
6. **Non-zero exit** when `fail-on` threshold is crossed — blocks the merge
   when configured as a required check.

## What it scans today

`v0.2.x` baseline:
- **Lyrie Shield** runs `scanRecalled` over every changed file in `diff` mode
  (or every text file in `full` mode), catching secret-like material and
  prompt-injection payloads at PR time.

`v0.2.1` (next PR):
- Pre-scan attack-surface mapping (`/understand`)
- Stages A–F exploitation validator (RAPTOR absorption)

`v0.2.2` (PR after that):
- Semgrep + CodeQL pre-screen
- 38 LLM Guard scanners ported into Shield
- Multi-language vuln scanners (Go / Python / JS-TS / C-C++ / PHP / Ruby)

## Ethics

Only run Lyrie against systems you own or are explicitly authorized to
test. The action defaults to **diff-scope** for exactly this reason —
running on PR-changed files inside your own repo is unambiguously safe.

## License

MIT — © OTT Cybersecurity LLC.

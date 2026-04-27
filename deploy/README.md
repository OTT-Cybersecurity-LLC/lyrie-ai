# Lyrie Execution Backends — deployment recipes

> _Lyrie.ai by **OTT Cybersecurity LLC** — https://lyrie.ai — MIT License._

Lyrie scans run **somewhere**. Today, that "somewhere" is pluggable:

| Backend | When to pick it |
|---|---|
| **Local** _(default)_ | Caller has Bun and the repo. Zero cost, zero network. |
| **Daytona** | Need ephemeral, snapshot-based devboxes (e.g. PR scans isolated from runner). |
| **Modal** | Need pure serverless. Pay-per-second. Burst-scale across hundreds of repos. |

Switch at runtime:

```bash
LYRIE_BACKEND=local      bun run action/runner.ts    # default
LYRIE_BACKEND=daytona    bun run action/runner.ts    # spin up Daytona, run there
LYRIE_BACKEND=modal      bun run action/runner.ts    # serverless on Modal
```

Inspect what's wired up:

```bash
bun run backend status
bun run backend list
bun run backend show daytona
bun run backend preflight modal
```

---

## Daytona

Files: [`daytona/lyrie.devcontainer.json`](daytona/lyrie.devcontainer.json)

```bash
# 1. One-time: publish the Lyrie image to GHCR (already done in CI).
#    ghcr.io/overthetopseo/lyrie-agent:latest

# 2. From your CI / shell:
export DAYTONA_API_KEY=your_daytona_api_key
export LYRIE_BACKEND=daytona
export LYRIE_DAYTONA_REGION=us-east-1     # optional
export LYRIE_DAYTONA_TTL_SECONDS=1800      # optional, default 30 min

bun run backend preflight daytona
bun run action/runner.ts
```

The Daytona backend will:

1. `POST /workspaces` to spin up a Lyrie devbox from the published image.
2. `POST /workspaces/{id}/exec` to run the action runner inside.
3. `GET /workspaces/{id}/files/lyrie-runs/lyrie.sarif` to fetch results.
4. `DELETE /workspaces/{id}` to tear down (TTL is the safety net).

---

## Modal

Files: [`modal/lyrie_modal.py`](modal/lyrie_modal.py)

```bash
# 1. One-time: deploy Lyrie's serverless function to your Modal account.
pip install modal
modal token new
modal deploy deploy/modal/lyrie_modal.py

# 2. From your CI / shell:
export LYRIE_BACKEND=modal
export MODAL_TOKEN_ID=<from `modal token list`>
export MODAL_TOKEN_SECRET=<from `modal token list`>

bun run backend preflight modal
bun run action/runner.ts
```

The Modal backend will:

1. `POST https://api.modal.com/v1/functions/invoke` with the run request.
2. Modal cold-starts a Lyrie container (image cached after first call).
3. Lyrie runs the scan inside the function.
4. Modal returns SARIF + markdown + cost.

---

## How the backend abstraction works

Single contract: `Backend` interface in `packages/core/src/backends/types.ts`.

```typescript
import { getBackend } from "@lyrie/core";

const b = getBackend("modal");          // or "daytona", or "local"
const r = await b.run({
  target:   "https://github.com/overthetopseo/lyrie-agent",
  scanMode: "full",
  scope:    "full",
  failOn:   "high",
});
console.log(r.findingCount, r.highestSeverity, r.costUsd);
```

Every backend returns the same `BackendRunResult` shape. Same SARIF, same Markdown, same Shield Doctrine — different host.

**No Docker. No vendor lock-in. Lyrie runs anywhere.**

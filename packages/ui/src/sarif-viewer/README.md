# Lyrie SARIF Viewer

A lightweight, framework-free web component that renders SARIF 2.1.0 scan results in-browser — no CI integration required.

## Overview

After running `lyrie scan`, results are written to a `.sarif` file. The viewer ingests that file and renders findings grouped by rule with severity badges and file/line references.

## Architecture

```
sarif-viewer/
├── types.ts        — SARIF 2.1.0 TypeScript types + FindingGroup view model
├── parse.ts        — parseSarif() + groupByRule() pure functions
├── SarifViewer.ts  — DOM-based renderer (no framework deps)
├── index.ts        — barrel export
└── README.md       — this file
```

## Usage

```typescript
import { SarifViewer } from "@lyrie/ui/sarif-viewer";

// Mount into any HTMLElement
const viewer = new SarifViewer(document.getElementById("sarif-output")!);

// Load from file input or fetch
const sarifJson = await fetch("/scan-results.sarif").then(r => r.text());
viewer.load(sarifJson);
```

## Acceptance Criteria (Issue #40)

- [x] Findings grouped by rule
- [x] Severity badge (error / warning / note / none)
- [x] Affected file + line linkable in `<code>` element
- [ ] CSS stylesheet (next iteration)
- [ ] File drop zone for drag-and-drop SARIF loading
- [ ] Export filtered results back to SARIF

## Notes

- No external dependencies. Works in any modern browser.
- `parseSarif()` throws on non-2.1.0 SARIF versions.
- Errors (`level: "error"`) are auto-expanded; others collapsed by default.

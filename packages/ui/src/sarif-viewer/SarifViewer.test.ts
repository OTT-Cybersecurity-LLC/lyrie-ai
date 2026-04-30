/**
 * Tests for SarifViewer DOM renderer.
 * Uses bun:test with happy-dom for DOM simulation.
 *
 * Note: happy-dom v20.9.0 has a bug where SelectorParser tries to call
 * `new this.window.SyntaxError(...)` but `this.window` is the happy-dom
 * Window object (not globalThis), so we must patch it before querying.
 */
// @ts-nocheck
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Window } from "happy-dom";
import type { SarifLog } from "./types";

// ---------------------------------------------------------------------------
// DOM bootstrap
// ---------------------------------------------------------------------------
let happyWindow: InstanceType<typeof Window>;

beforeEach(() => {
  happyWindow = new Window({ url: "https://lyrie.ai" });
  // Patch missing builtins that happy-dom's SelectorParser needs
  (happyWindow as any).SyntaxError = SyntaxError;
  (happyWindow as any).TypeError = TypeError;
  (happyWindow as any).Error = Error;

  const doc = happyWindow.document;
  (globalThis as any).document = doc;
  (globalThis as any).window = happyWindow;
  (globalThis as any).HTMLElement = happyWindow.HTMLElement;
});

afterEach(async () => {
  await happyWindow.happyDOM.abort();
  delete (globalThis as any).document;
  delete (globalThis as any).window;
  delete (globalThis as any).HTMLElement;
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EMPTY_SARIF: SarifLog = {
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "EmptyScanner", rules: [] } },
      results: [],
    },
  ],
};

const SINGLE_ERROR: SarifLog = {
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Lyrie",
          version: "0.1.0",
          rules: [
            {
              id: "SQL001",
              name: "SqlInjection",
              shortDescription: { text: "SQL injection vulnerability" },
              defaultConfiguration: { level: "error" },
              helpUri: "https://lyrie.ai/rules/SQL001",
            },
          ],
        },
      },
      results: [
        {
          ruleId: "SQL001",
          level: "error",
          message: { text: "SQL injection in login form" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/auth/login.ts" },
                region: { startLine: 42 },
              },
            },
          ],
        },
      ],
    },
  ],
};

const MULTI_SEVERITY: SarifLog = {
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "MultiScan",
          rules: [
            { id: "E1", name: "ErrorRule", defaultConfiguration: { level: "error" } },
            { id: "W1", name: "WarnRule", defaultConfiguration: { level: "warning" } },
            { id: "N1", name: "NoteRule", defaultConfiguration: { level: "note" } },
          ],
        },
      },
      results: [
        { ruleId: "W1", level: "warning", message: { text: "warning msg" } },
        { ruleId: "E1", level: "error", message: { text: "error msg" } },
        { ruleId: "N1", level: "note", message: { text: "note msg" } },
      ],
    },
  ],
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeSarifViewer(container: HTMLElement) {
  const { SarifViewer } = await import("./SarifViewer");
  return new SarifViewer(container);
}

function makeContainer(): HTMLElement {
  return (globalThis as any).document.createElement("div");
}

/** Walk the DOM tree and collect elements whose className includes `cls` */
function findByClass(root: HTMLElement, cls: string): HTMLElement[] {
  const results: HTMLElement[] = [];
  function walk(node: HTMLElement) {
    if (node.nodeType === 1) {
      const classes = (node.className || "").split(/\s+/);
      if (classes.includes(cls)) results.push(node);
      for (let i = 0; i < node.childNodes.length; i++) {
        walk(node.childNodes[i] as HTMLElement);
      }
    }
  }
  walk(root);
  return results;
}

/** Walk the DOM and collect elements by tag name */
function findByTag(root: HTMLElement, tag: string): HTMLElement[] {
  const results: HTMLElement[] = [];
  function walk(node: HTMLElement) {
    if (node.nodeType === 1) {
      if (node.tagName && node.tagName.toLowerCase() === tag.toLowerCase()) {
        results.push(node);
      }
      for (let i = 0; i < node.childNodes.length; i++) {
        walk(node.childNodes[i] as HTMLElement);
      }
    }
  }
  walk(root);
  return results;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SarifViewer", () => {
  it("renders a section per run", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    const sections = findByClass(el, "sarif-run");
    expect(sections.length).toBe(1);
  });

  it("renders tool name as h2 header", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    const h2s = findByTag(el, "h2");
    expect(h2s.length).toBeGreaterThan(0);
    expect(h2s[0].textContent).toContain("Lyrie");
    expect(h2s[0].textContent).toContain("0.1.0");
  });

  it("shows 'No findings' when run has no results", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(EMPTY_SARIF);

    expect(el.textContent).toContain("No findings");
  });

  it("renders a sarif-group per rule", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    const groups = findByClass(el, "sarif-group");
    expect(groups.length).toBe(1);
  });

  it("auto-expands error groups (open=true)", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    const errorGroups = findByClass(el, "sarif-level-error");
    expect(errorGroups.length).toBeGreaterThan(0);
    expect((errorGroups[0] as any).open).toBe(true);
  });

  it("does not auto-expand warning groups (open=false)", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(MULTI_SEVERITY);

    const warnGroups = findByClass(el, "sarif-level-warning");
    expect(warnGroups.length).toBeGreaterThan(0);
    expect((warnGroups[0] as any).open).toBe(false);
  });

  it("renders badge with severity label", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    const badges = findByClass(el, "sarif-badge");
    expect(badges.length).toBeGreaterThan(0);
    expect(badges[0].textContent).toContain("ERROR");
  });

  it("renders file:line in code element", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    const locs = findByClass(el, "sarif-location");
    expect(locs.length).toBeGreaterThan(0);
    expect(locs[0].textContent).toBe("src/auth/login.ts:42");
  });

  it("renders result message text", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    expect(el.textContent).toContain("SQL injection in login form");
  });

  it("renders helpUri as an anchor", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(SINGLE_ERROR);

    const links = findByClass(el, "sarif-help-link");
    expect(links.length).toBeGreaterThan(0);
    expect((links[0] as HTMLAnchorElement).href).toBe("https://lyrie.ai/rules/SQL001");
  });

  it("sorts groups by severity — error first, then warning, then note", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(MULTI_SEVERITY);

    const groups = findByClass(el, "sarif-group");
    expect(groups.length).toBe(3);
    expect(groups[0].className).toContain("sarif-level-error");
    expect(groups[1].className).toContain("sarif-level-warning");
    expect(groups[2].className).toContain("sarif-level-note");
  });

  it("replaces previous render on second load()", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(EMPTY_SARIF);
    const firstHtml = el.innerHTML;
    viewer.load(SINGLE_ERROR);
    const secondHtml = el.innerHTML;

    expect(firstHtml).not.toBe(secondHtml);
    expect(findByClass(el, "sarif-run").length).toBe(1);
  });

  it("handles result without a location gracefully", async () => {
    const noLoc: SarifLog = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "Scanner" } },
          results: [{ ruleId: "R1", level: "warning", message: { text: "no location" } }],
        },
      ],
    };
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    expect(() => viewer.load(noLoc)).not.toThrow();
    expect(el.textContent).toContain("no location");
  });

  it("handles SARIF JSON string as input", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    viewer.load(JSON.stringify(SINGLE_ERROR));

    expect(findByClass(el, "sarif-run").length).toBe(1);
  });

  it("propagates parse error on invalid SARIF", async () => {
    const el = makeContainer();
    const viewer = await makeSarifViewer(el);
    expect(() =>
      viewer.load(JSON.stringify({ version: "1.0.0", runs: [] }))
    ).toThrow("Unsupported SARIF version");
  });
});

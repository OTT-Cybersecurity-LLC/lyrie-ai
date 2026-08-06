/**
 * Lyrie Hack — Supply-Chain Reachability Analysis.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Cross-references a `DependencyGraph` (from `extractDependencyGraph`) against
 * a caller-supplied list of known-vulnerable packages and determines whether
 * each vulnerable package/version is actually REACHABLE — i.e. imported or
 * required somewhere in the scanned codebase's source files — rather than
 * merely present in a manifest.
 *
 * This closes the gap between "vulnerable dependency exists" (noisy, most
 * SCA tools stop here) and "vulnerable dependency is exploitable" (the
 * question that actually matters for prioritization).
 *
 * Design:
 *   1. For every `DependencyPackage` in the graph, check whether any entry
 *      in the caller-supplied `VulnerablePackageEntry[]` list matches its
 *      name + ecosystem, and whether its version falls inside the entry's
 *      `vulnerableVersionRange`.
 *   2. For every match, grep the source tree under `rootDir` for import /
 *      require statements referencing that package name, per-ecosystem
 *      import syntax (JS/TS: `require(...)`, `import ... from "..."`,
 *      dynamic `import(...)`; Python: `import pkg`, `from pkg import ...`;
 *      Go: `import "pkg"`; Ruby: `require "pkg"`; PHP: `use Pkg\...` /
 *      `require "pkg"`).
 *   3. Assign a reachability verdict + confidence:
 *        - reachable=true,  confidence="high"   → direct import/require found.
 *        - reachable=false, confidence="medium"  → not directly imported, but
 *          the package is a transitive dependency (scope !== "direct") of
 *          some package that *is* reachable — i.e. plausibly reachable via
 *          another module's import graph, just not provably from source
 *          grep alone.
 *        - reachable=false, confidence="low"     → present only in a
 *          manifest/lockfile with no import evidence anywhere — likely dead
 *          weight, lowest exploitation priority.
 *
 * Pure-static, no network, no execution, no mutation of the target tree.
 * The only "reads" performed are directory walks + file reads of source
 * files under `rootDir`, to grep for import statements.
 *
 * © OTT Cybersecurity LLC.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

import type { DependencyGraph, DependencyPackage, Ecosystem } from "./dependency-graph";

export const REACHABILITY_VERSION = "lyrie-reachability-1.0.0";

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * A known-vulnerable package/version entry, supplied by the caller (e.g.
 * sourced from `packages/core/src/pentest/threat-intel` or any other feed).
 * This module performs no CVE lookups of its own — it is offline/network-free
 * by design.
 */
export interface VulnerablePackageEntry {
  name: string;
  ecosystem: Ecosystem;
  /**
   * Version range in which this package is vulnerable. Supported syntaxes:
   *   - exact version:            "1.2.3"
   *   - comparator:               ">=1.0.0", "<2.0.0", "<=1.5.0", ">1.0.0"
   *   - caret range:              "^1.2.3"   (>=1.2.3 <2.0.0, same-major)
   *   - tilde range:              "~1.2.3"   (>=1.2.3 <1.3.0, same-major.minor)
   *   - AND of two comparators:   ">=1.0.0 <2.0.0" (space-separated, both must hold)
   *   - dash range (inclusive):   "1.0.0 - 1.9.9"
   *   - wildcard / empty:         "*" or "" (always vulnerable)
   *
   * See `isVersionInRange` for exactly what is and is not supported.
   */
  vulnerableVersionRange: string;
  cve: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
}

export type ReachabilityConfidence = "high" | "medium" | "low";

export interface ReachabilityResult {
  packageName: string;
  version?: string;
  cve: string;
  severity: VulnerablePackageEntry["severity"];
  ecosystem: Ecosystem;
  manifest: string;
  reachable: boolean;
  /** File paths (relative to rootDir) where the package is imported/required. Empty if not reachable. */
  reachedFrom: string[];
  confidence: ReachabilityConfidence;
}

// ─── Directory walk (source-file discovery) ────────────────────────────────

const IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  ".venv",
  "venv",
  "env",
  "__pycache__",
  "dist",
  "build",
  "target",
  ".next",
  ".cache",
  ".tox",
  ".idea",
  ".vscode",
  "vendor",
]);

/** Source file extensions we scan for import/require evidence, per ecosystem family. */
const JS_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"];
const PY_EXTENSIONS = [".py"];
const GO_EXTENSIONS = [".go"];
const RUBY_EXTENSIONS = [".rb"];
const PHP_EXTENSIONS = [".php"];

const ALL_SCANNED_EXTENSIONS = new Set([
  ...JS_EXTENSIONS,
  ...PY_EXTENSIONS,
  ...GO_EXTENSIONS,
  ...RUBY_EXTENSIONS,
  ...PHP_EXTENSIONS,
]);

const DEFAULT_MAX_FILES = 20000;
const DEFAULT_MAX_DEPTH = 40;

function extensionOf(name: string): string {
  const idx = name.lastIndexOf(".");
  return idx >= 0 ? name.slice(idx) : "";
}

/** Walk `root` and return absolute paths of every source file worth grepping for imports. */
function findSourceFiles(root: string, maxDepth: number, maxFiles: number): string[] {
  const out: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];

  while (queue.length > 0 && out.length < maxFiles) {
    const next = queue.shift()!;
    let entries: string[];
    try {
      entries = readdirSync(next.dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      if (IGNORE_DIRS.has(name)) continue;
      const abs = join(next.dir, name);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (next.depth < maxDepth) queue.push({ dir: abs, depth: next.depth + 1 });
      } else if (ALL_SCANNED_EXTENSIONS.has(extensionOf(name))) {
        out.push(abs);
        if (out.length >= maxFiles) break;
      }
    }
  }
  return out;
}

/** Map an ecosystem to the file extensions whose import syntax applies to it. */
function extensionsForEcosystem(eco: Ecosystem): string[] {
  switch (eco) {
    case "npm":
      return JS_EXTENSIONS;
    case "pip":
      return PY_EXTENSIONS;
    case "go":
      return GO_EXTENSIONS;
    case "ruby":
      return RUBY_EXTENSIONS;
    case "php":
      return PHP_EXTENSIONS;
    // cargo/maven/gradle: no cheap universal grep-based import heuristic
    // implemented yet — no reachable extensions means these ecosystems will
    // never be reported "reachable" (falls back to manifest-only evidence).
    default:
      return [];
  }
}

/**
 * Escape a package name for safe embedding inside a RegExp pattern.
 */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build the set of import/require regexes that indicate `pkgName` is
 * directly imported in a source file, for the given ecosystem.
 *
 * JS/TS: require("pkg"), require("pkg/sub"), import ... from "pkg",
 *        import "pkg", dynamic import("pkg"), export ... from "pkg".
 *        Scoped packages (@scope/name) matched as a whole; subpath imports
 *        ("pkg/sub/path") also match on the package name prefix.
 * Python: import pkg, import pkg.sub, from pkg import x, from pkg.sub import x.
 * Go: import "pkg" or grouped import ( "pkg" ... ) — matched by suffix since
 *     Go import paths are full module paths (e.g. "github.com/org/pkg").
 * Ruby: require "pkg", require_relative not included (relative, not a gem).
 * PHP: use Pkg\..., require/include with the package's composer vendor dir
 *      is not reliably graspable via import syntax, so PHP falls back to a
 *      `use <Namespace>` heuristic derived from the vendor/package segment.
 */
function buildImportPatterns(pkgName: string, eco: Ecosystem): RegExp[] {
  const esc = escapeRegex(pkgName);
  switch (eco) {
    case "npm": {
      // Matches "pkg" or "pkg/anything" as the imported module specifier,
      // for both single and double quoted strings.
      const specifier = `${esc}(?:/[^"'\`]*)?`;
      return [
        new RegExp(`\\brequire\\(\\s*["'\`]${specifier}["'\`]\\s*\\)`),
        new RegExp(`\\bimport\\s*\\(\\s*["'\`]${specifier}["'\`]\\s*\\)`), // dynamic import()
        new RegExp(`\\bimport\\b[^;]*?\\bfrom\\s*["'\`]${specifier}["'\`]`), // import x from "pkg"
        new RegExp(`\\bimport\\s*["'\`]${specifier}["'\`]`), // bare side-effect import "pkg"
        new RegExp(`\\bexport\\b[^;]*?\\bfrom\\s*["'\`]${specifier}["'\`]`), // export ... from "pkg"
      ];
    }
    case "pip": {
      // Python import names use underscores/dots; package distribution name
      // and import name can differ, but we match the common case where they
      // align (as most manifests use the import-equivalent name).
      const mod = esc.replace(/-/g, "[-_]");
      return [
        new RegExp(`^\\s*import\\s+${mod}(?:\\.[\\w.]+)?(?:\\s+as\\s+\\w+)?\\s*$`, "m"),
        new RegExp(`^\\s*import\\s+${mod}(?:\\.[\\w.]+)?\\s*,`, "m"), // import a, pkg, b
        new RegExp(`^\\s*from\\s+${mod}(?:\\.[\\w.]+)?\\s+import\\b`, "m"),
      ];
    }
    case "go": {
      // Go module paths are typically the full import path (e.g.
      // github.com/gin-gonic/gin). Match either an exact quoted import or
      // one ending in "/<lastSegment>" for cases where only the last path
      // segment was recorded as the package name.
      const lastSegment = pkgName.split("/").pop() ?? pkgName;
      const escSeg = escapeRegex(lastSegment);
      return [
        new RegExp(`["\`]${esc}["\`]`),
        new RegExp(`/${escSeg}["\`]`),
      ];
    }
    case "ruby":
      return [new RegExp(`\\brequire\\s+["']${esc}["']`)];
    case "php": {
      // composer package names are "vendor/name"; PHP namespace usage (`use
      // Vendor\Name\...`) typically PascalCases each segment, which we can't
      // derive reliably, so we match on the raw vendor/name segments loosely
      // appearing in a `use` statement or a direct string require/include.
      const segments = pkgName.split("/").map(escapeRegex);
      const nsGuess = segments.join("\\\\");
      return [
        new RegExp(`\\buse\\s+${nsGuess}`, "i"),
        new RegExp(`["']${esc}["']`),
      ];
    }
    default:
      return [];
  }
}

/**
 * Grep the source tree under `rootDir` for direct import/require evidence of
 * `pkgName` for the given ecosystem. Returns relative file paths (relative to
 * `rootDir`) where evidence was found, capped at `maxHits`.
 */
function findImportEvidence(
  rootDir: string,
  sourceFiles: string[],
  pkgName: string,
  eco: Ecosystem,
  maxHits = 25,
): string[] {
  const patterns = buildImportPatterns(pkgName, eco);
  if (patterns.length === 0) return [];

  const extensions = new Set(extensionsForEcosystem(eco));
  const hits: string[] = [];

  for (const abs of sourceFiles) {
    if (hits.length >= maxHits) break;
    if (!extensions.has(extensionOf(abs))) continue;

    let content: string;
    try {
      content = readFileSync(abs, "utf8");
    } catch {
      continue;
    }

    for (const re of patterns) {
      if (re.test(content)) {
        hits.push(relative(rootDir, abs) || abs);
        break;
      }
    }
  }

  return hits;
}

// ─── Minimal semver-ish range matcher ──────────────────────────────────────
//
// Lyrie deliberately does not pull in a `semver` (or any new) npm dependency
// for this. A near-identical single-comparator matcher already exists at
// `packages/core/src/pentest/threat-intel/client.ts` (`versionAffected`),
// but it does not support two-clause AND ranges like ">=1.0.0 <2.0.0", which
// the task spec for this module explicitly requires. Rather than duplicate
// single-comparator logic in two places with subtly different behavior,
// this module implements its own comparator that is a strict superset of
// that behavior (single comparator, dash range, caret, tilde, exact, "*")
// PLUS a space-separated AND of exactly two comparators.
//
// Supported:
//   - ""  or "*"                     → always in range
//   - "1.2.3"                        → exact match only
//   - ">=1.2.3" / ">1.2.3" / "<1.2.3" / "<=1.2.3" / "=1.2.3"
//   - "^1.2.3"                       → >=1.2.3, <(next major)
//   - "~1.2.3"                       → >=1.2.3, <(next minor)
//   - "1.0.0 - 2.0.0"                → inclusive dash range
//   - ">=1.0.0 <2.0.0"               → AND of exactly two single comparators
//
// NOT supported (documented, not silently guessed):
//   - OR ranges ("||"), e.g. "<1.0.0 || >=2.0.0"
//   - pre-release/build-metadata ordering semantics (e.g. 1.0.0-beta.1 vs
//     1.0.0-beta.2) — pre-release/build suffixes are stripped and ignored
//     for comparison purposes, so "1.0.0-beta" is treated as "1.0.0"
//   - "x"/"X"/partial-version wildcards (e.g. "1.x", "1.2.x")
//   - npm's full range grammar (build metadata, complex set operators)
//   - version strings with more than 3 numeric segments (4th+ ignored)

type SemverTuple = [number, number, number];

function parseSemver(raw: string): SemverTuple {
  const cleaned = raw.trim().replace(/^v/i, "");
  const numericPart = cleaned.split(/[-+]/)[0]; // strip pre-release/build metadata
  const parts = numericPart.split(".").slice(0, 3).map((n) => {
    const parsed = parseInt(n, 10);
    return Number.isFinite(parsed) ? parsed : 0;
  });
  while (parts.length < 3) parts.push(0);
  return [parts[0], parts[1], parts[2]];
}

function compareSemver(a: SemverTuple, b: SemverTuple): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

/** Evaluate a single comparator clause (e.g. ">=1.2.3") against a parsed version. */
function evaluateComparator(v: SemverTuple, clause: string): boolean {
  const trimmed = clause.trim();
  if (!trimmed || trimmed === "*") return true;

  const m = trimmed.match(/^(<=|>=|<|>|=|\^|~)?\s*([0-9].*)$/);
  if (!m) return false;
  const op = m[1] ?? "=";
  const target = parseSemver(m[2]);
  const c = compareSemver(v, target);

  switch (op) {
    case "<":
      return c < 0;
    case "<=":
      return c <= 0;
    case ">":
      return c > 0;
    case ">=":
      return c >= 0;
    case "=":
      return c === 0;
    case "^":
      // Caret: same major version, >= target.
      return c >= 0 && v[0] === target[0];
    case "~":
      // Tilde: same major.minor, >= target.
      return c >= 0 && v[0] === target[0] && v[1] === target[1];
    default:
      return false;
  }
}

/**
 * Determine whether `version` falls inside `range`. See the module-level
 * comment above for exactly what range syntax is supported.
 */
export function isVersionInRange(version: string, range: string): boolean {
  const trimmed = range.trim();
  if (!trimmed || trimmed === "*") return true;

  const v = parseSemver(version);

  // Dash range: "A - B" (inclusive).
  if (/\s+-\s+/.test(trimmed)) {
    const [lo, hi] = trimmed.split(/\s+-\s+/).map((s) => parseSemver(s));
    return compareSemver(v, lo) >= 0 && compareSemver(v, hi) <= 0;
  }

  // AND of two whitespace-separated comparators, e.g. ">=1.0.0 <2.0.0".
  // Split on whitespace that is NOT immediately preceded by a comparator
  // operator's numeric target — i.e. split into tokens that each start
  // with an operator or a digit.
  const clauses = trimmed.split(/\s+/).filter(Boolean);
  if (clauses.length === 2) {
    return evaluateComparator(v, clauses[0]) && evaluateComparator(v, clauses[1]);
  }

  // Single comparator / exact / caret / tilde.
  return evaluateComparator(v, trimmed);
}

/**
 * True if `name`/`ecosystem` appears anywhere in the graph with a
 * direct/dev/peer/optional scope (i.e. it has its own manifest-declared
 * entry, independent of any transitive/lockfile row for the same name).
 */
function hasDirectManifestEntry(graph: DependencyGraph, name: string, ecosystem: Ecosystem): boolean {
  const lower = name.toLowerCase();
  return graph.packages.some(
    (p) =>
      p.ecosystem === ecosystem &&
      p.name.toLowerCase() === lower &&
      (p.scope === "direct" || p.scope === "dev" || p.scope === "peer" || p.scope === "optional"),
  );
}

// ─── Core analysis ──────────────────────────────────────────────────────────

export interface ReachabilityOptions {
  /** Max source files to walk (defaults to 20000). */
  maxFiles?: number;
  /** Max directory depth to walk (defaults to 40). */
  maxDepth?: number;
  /** Max file-path hits to record per package (defaults to 25). */
  maxHitsPerPackage?: number;
}

/**
 * Cross-reference `graph.packages` against `vulnPackages` and determine
 * whether each matched vulnerable package is actually reachable (imported)
 * from source under `rootDir`.
 *
 * Pure function w.r.t. its inputs (no mutation of `graph` or `vulnPackages`);
 * performs read-only filesystem access under `rootDir` to grep for import
 * evidence. No network access.
 */
export function analyzeReachability(
  graph: DependencyGraph,
  vulnPackages: VulnerablePackageEntry[],
  rootDir: string,
  options: ReachabilityOptions = {},
): ReachabilityResult[] {
  const root = resolve(rootDir);
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxHitsPerPackage = options.maxHitsPerPackage ?? 25;

  // Index vulnerable entries by ecosystem::name for O(1) lookup per package.
  const vulnIndex = new Map<string, VulnerablePackageEntry[]>();
  for (const entry of vulnPackages) {
    const key = `${entry.ecosystem}::${entry.name.toLowerCase()}`;
    const list = vulnIndex.get(key);
    if (list) list.push(entry);
    else vulnIndex.set(key, [entry]);
  }

  if (vulnIndex.size === 0) return [];

  const sourceFiles = findSourceFiles(root, maxDepth, maxFiles);

  // Determine which package names (per ecosystem) are "reachable" at all,
  // to support medium-confidence transitive inference below.
  const reachableNameSet = new Set<string>(); // key: `${ecosystem}::${name}`
  const importEvidenceCache = new Map<string, string[]>(); // key: `${ecosystem}::${name}`

  function evidenceFor(name: string, eco: Ecosystem): string[] {
    const key = `${eco}::${name.toLowerCase()}`;
    const cached = importEvidenceCache.get(key);
    if (cached) return cached;
    const found = findImportEvidence(root, sourceFiles, name, eco, maxHitsPerPackage);
    importEvidenceCache.set(key, found);
    if (found.length > 0) reachableNameSet.add(key);
    return found;
  }

  // Pre-scan every package in the graph once so we know, for scope-based
  // transitive inference, which *direct* packages are reachable.
  for (const pkg of graph.packages) {
    if (pkg.scope === "direct" || pkg.scope === "dev" || pkg.scope === "peer" || pkg.scope === "optional") {
      evidenceFor(pkg.name, pkg.ecosystem);
    }
  }

  const results: ReachabilityResult[] = [];

  for (const pkg of graph.packages) {
    const key = `${pkg.ecosystem}::${pkg.name.toLowerCase()}`;
    const matches = vulnIndex.get(key);
    if (!matches || matches.length === 0) continue;

    for (const vuln of matches) {
      if (pkg.version && !isVersionInRange(pkg.version, vuln.vulnerableVersionRange)) {
        continue; // installed version is outside the vulnerable range
      }

      const reachedFrom = evidenceFor(pkg.name, pkg.ecosystem);
      const directlyReachable = reachedFrom.length > 0;

      let reachable: boolean;
      let confidence: ReachabilityConfidence;

      if (directlyReachable) {
        reachable = true;
        confidence = "high";
      } else if (pkg.scope === "transitive" && !hasDirectManifestEntry(graph, pkg.name, pkg.ecosystem)) {
        // Not directly imported, and this package name has NO direct/dev/
        // peer/optional manifest entry we could check for import evidence
        // (it only exists as a transitive row in a lockfile). We can't prove
        // which direct package pulled it in from a lockfile entry alone
        // (that requires a full dependency tree, which lockfile parsing in
        // dependency-graph.ts does not currently preserve), so treat it as
        // plausibly reachable via *some* direct import when at least one
        // direct package in the same ecosystem has import evidence — medium
        // confidence either way. If this exact package name DOES also have a
        // direct manifest entry, `directlyReachable` above already reflects
        // its true per-name import evidence, so falling through here would
        // wrongly borrow confidence from unrelated packages — handled by the
        // `else` branch instead.
        const anyDirectReachable = Array.from(reachableNameSet).some((k) => k.startsWith(`${pkg.ecosystem}::`));
        reachable = false;
        confidence = anyDirectReachable ? "medium" : "low";
      } else {
        // Direct/dev/peer/optional manifest entry (or a transitive entry
        // whose package name is also a direct entry elsewhere) with zero
        // import evidence anywhere in the scanned tree — likely genuinely
        // dead code / unused dependency.
        reachable = false;
        confidence = "low";
      }

      results.push({
        packageName: pkg.name,
        version: pkg.version,
        cve: vuln.cve,
        severity: vuln.severity,
        ecosystem: pkg.ecosystem,
        manifest: pkg.manifest,
        reachable,
        reachedFrom,
        confidence,
      });
    }
  }

  return results;
}

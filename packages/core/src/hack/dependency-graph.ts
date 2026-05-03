/**
 * Lyrie Hack — Dependency Graph extractor.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Builds a small, non-network dependency graph for `lyrie hack <target>`.
 * Detects:
 *   - package.json          (npm)
 *   - package-lock.json     (npm)
 *   - yarn.lock             (npm via yarn)
 *   - pnpm-lock.yaml        (npm via pnpm)
 *   - requirements.txt      (pip)
 *   - pyproject.toml        (pip)
 *   - Pipfile               (pip)
 *   - go.mod                (go)
 *   - Cargo.toml            (cargo)
 *   - pom.xml               (java/maven)
 *   - build.gradle(.kts)    (java/gradle)
 *   - Gemfile               (ruby)
 *   - composer.json         (php)
 *
 * Pure-static: no network, no execution.
 *
 * © OTT Cybersecurity LLC.
 */

import { existsSync, readFileSync, statSync, readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";

export type Ecosystem =
  | "npm"
  | "pip"
  | "go"
  | "cargo"
  | "maven"
  | "gradle"
  | "ruby"
  | "php"
  | "unknown";

export interface DependencyPackage {
  name: string;
  version?: string;
  ecosystem: Ecosystem;
  manifest: string;
  /** Direct vs transitive (best-effort; lockfiles produce transitive). */
  scope: "direct" | "dev" | "peer" | "optional" | "transitive";
}

export interface DependencyGraph {
  root: string;
  packages: DependencyPackage[];
  /** Manifests that were actually read. */
  manifestsFound: string[];
  /** Ecosystems detected (for branching downstream). */
  ecosystems: Ecosystem[];
  generatedAt: string;
  signature: "Lyrie.ai by OTT Cybersecurity LLC";
}

export const DEPENDENCY_GRAPH_VERSION = "lyrie-depgraph-1.0.0";

export interface DependencyGraphOptions {
  root: string;
  /** Max manifests to walk into (defaults to 200). */
  maxManifests?: number;
  /** Max depth for nested manifest discovery. */
  maxDepth?: number;
}

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

/**
 * Walk a project root and extract every dependency manifest into a unified graph.
 */
export function extractDependencyGraph(
  opts: DependencyGraphOptions,
): DependencyGraph {
  const root = resolve(opts.root);
  const maxManifests = opts.maxManifests ?? 200;
  const maxDepth = opts.maxDepth ?? 4;

  const manifestPaths = findManifests(root, maxDepth, maxManifests);
  const packages: DependencyPackage[] = [];
  const ecosystems = new Set<Ecosystem>();
  const manifestsFound: string[] = [];

  for (const abs of manifestPaths) {
    const rel = relative(root, abs) || abs;
    const base = rel.split("/").pop()!;
    let added = 0;

    try {
      switch (base) {
        case "package.json":
          added = readPackageJson(abs, rel, packages);
          if (added > 0) ecosystems.add("npm");
          break;
        case "package-lock.json":
          added = readPackageLockJson(abs, rel, packages);
          if (added > 0) ecosystems.add("npm");
          break;
        case "yarn.lock":
          added = readYarnLock(abs, rel, packages);
          if (added > 0) ecosystems.add("npm");
          break;
        case "pnpm-lock.yaml":
          added = readPnpmLock(abs, rel, packages);
          if (added > 0) ecosystems.add("npm");
          break;
        case "requirements.txt":
          added = readRequirementsTxt(abs, rel, packages);
          if (added > 0) ecosystems.add("pip");
          break;
        case "pyproject.toml":
          added = readPyprojectToml(abs, rel, packages);
          if (added > 0) ecosystems.add("pip");
          break;
        case "Pipfile":
          added = readPipfile(abs, rel, packages);
          if (added > 0) ecosystems.add("pip");
          break;
        case "go.mod":
          added = readGoMod(abs, rel, packages);
          if (added > 0) ecosystems.add("go");
          break;
        case "Cargo.toml":
          added = readCargoToml(abs, rel, packages);
          if (added > 0) ecosystems.add("cargo");
          break;
        case "pom.xml":
          added = readPomXml(abs, rel, packages);
          if (added > 0) ecosystems.add("maven");
          break;
        case "build.gradle":
        case "build.gradle.kts":
          added = readGradle(abs, rel, packages);
          if (added > 0) ecosystems.add("gradle");
          break;
        case "Gemfile":
          added = readGemfile(abs, rel, packages);
          if (added > 0) ecosystems.add("ruby");
          break;
        case "composer.json":
          added = readComposerJson(abs, rel, packages);
          if (added > 0) ecosystems.add("php");
          break;
      }
      if (added > 0) manifestsFound.push(rel);
    } catch {
      // ignore parse errors per-manifest
    }
  }

  return {
    root,
    packages: dedupe(packages),
    manifestsFound,
    ecosystems: Array.from(ecosystems),
    generatedAt: new Date().toISOString(),
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

// ─── manifest discovery ──────────────────────────────────────────────────────

const MANIFEST_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "requirements.txt",
  "pyproject.toml",
  "Pipfile",
  "go.mod",
  "Cargo.toml",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "Gemfile",
  "composer.json",
]);

function findManifests(root: string, maxDepth: number, max: number): string[] {
  const out: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];

  while (queue.length > 0 && out.length < max) {
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
      } else if (MANIFEST_NAMES.has(name)) {
        out.push(abs);
        if (out.length >= max) break;
      }
    }
  }
  return out;
}

// ─── parsers ─────────────────────────────────────────────────────────────────

function readPackageJson(abs: string, rel: string, out: DependencyPackage[]): number {
  const obj = JSON.parse(readFileSync(abs, "utf8"));
  let added = 0;
  for (const [key, scope] of [
    ["dependencies", "direct"],
    ["devDependencies", "dev"],
    ["peerDependencies", "peer"],
    ["optionalDependencies", "optional"],
  ] as const) {
    const sec = (obj?.[key] ?? {}) as Record<string, string>;
    for (const [name, version] of Object.entries(sec)) {
      out.push({ name, version: stripRange(version), ecosystem: "npm", manifest: rel, scope });
      added++;
    }
  }
  return added;
}

function readPackageLockJson(abs: string, rel: string, out: DependencyPackage[]): number {
  const obj = JSON.parse(readFileSync(abs, "utf8"));
  let added = 0;
  // npm v7+ has "packages"; v6 has "dependencies".
  const packages = obj?.packages as Record<string, { version?: string; dev?: boolean }> | undefined;
  if (packages) {
    for (const [path, meta] of Object.entries(packages)) {
      if (path === "" || !path.startsWith("node_modules/")) continue;
      const name = path.replace(/^node_modules\//, "").replace(/\/node_modules\/.*$/, "");
      if (!name) continue;
      out.push({
        name,
        version: meta?.version,
        ecosystem: "npm",
        manifest: rel,
        scope: meta?.dev ? "dev" : "transitive",
      });
      added++;
    }
  } else {
    const deps = obj?.dependencies as Record<string, { version?: string; dev?: boolean }> | undefined;
    if (deps) {
      for (const [name, meta] of Object.entries(deps)) {
        out.push({
          name,
          version: meta?.version,
          ecosystem: "npm",
          manifest: rel,
          scope: meta?.dev ? "dev" : "transitive",
        });
        added++;
      }
    }
  }
  return added;
}

function readYarnLock(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  // yarn v1 entries: `"foo@^1.2.3", "foo@^1.0.0":\n  version "1.2.3"`
  const re = /^"?([@\w][^@"\n]*?)@[^\n"]+"?:?\s*\n(?:\s+resolution:[^\n]*\n)?\s+version[: ]+"?([^"\n]+)"?/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({ name: m[1], version: m[2], ecosystem: "npm", manifest: rel, scope: "transitive" });
    added++;
    if (added > 5000) break;
  }
  return added;
}

function readPnpmLock(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  // pnpm format: keys like `/foo/1.2.3:` or `/@scope/foo/1.2.3:`
  const re = /^\s+\/((?:@[\w.-]+\/)?[\w.-]+)\/([\d.]+(?:-[\w.-]+)?)[:_]/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({ name: m[1], version: m[2], ecosystem: "npm", manifest: rel, scope: "transitive" });
    added++;
    if (added > 5000) break;
  }
  return added;
}

function readRequirementsTxt(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  for (const line of text.split("\n")) {
    const trimmed = line.split("#")[0].trim();
    if (!trimmed || trimmed.startsWith("-")) continue;
    // Examples: foo==1.2.3, foo>=1.2, foo, foo[extras]==1.0
    const m = trimmed.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:([<>=!~]=?)\s*([\d.\w]+))?/);
    if (!m) continue;
    out.push({
      name: m[1],
      version: m[3] ?? undefined,
      ecosystem: "pip",
      manifest: rel,
      scope: "direct",
    });
    added++;
  }
  return added;
}

function readPyprojectToml(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  // poetry style: [tool.poetry.dependencies] -> name = "^1.2.3"
  const sectionStarts = [
    /\[tool\.poetry\.dependencies\]/,
    /\[tool\.poetry\.dev-dependencies\]/,
    /\[project\.dependencies\]/,
  ];
  // PEP-621 style: dependencies = ["foo>=1", ...]
  const arrMatch = text.match(/\bdependencies\s*=\s*\[([^\]]*)\]/);
  if (arrMatch) {
    for (const raw of arrMatch[1].split(",")) {
      const item = raw.trim().replace(/^["']|["']$/g, "");
      if (!item) continue;
      const m = item.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:([<>=!~]=?)\s*([\d.\w]+))?/);
      if (m) {
        out.push({
          name: m[1],
          version: m[3] ?? undefined,
          ecosystem: "pip",
          manifest: rel,
          scope: "direct",
        });
        added++;
      }
    }
  }
  for (const re of sectionStarts) {
    const idx = text.search(re);
    if (idx < 0) continue;
    const tail = text.slice(idx);
    const stop = tail.search(/\n\[/);
    const block = stop > 0 ? tail.slice(0, stop) : tail;
    const lineRe = /^\s*([A-Za-z0-9_.\-]+)\s*=\s*["']?([^"'\n#]+)["']?/gm;
    let m: RegExpExecArray | null;
    while ((m = lineRe.exec(block)) !== null) {
      const name = m[1];
      if (name.toLowerCase() === "python") continue;
      out.push({
        name,
        version: stripRange(m[2].trim()),
        ecosystem: "pip",
        manifest: rel,
        scope: "direct",
      });
      added++;
    }
  }
  return added;
}

function readPipfile(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  const sections = ["[packages]", "[dev-packages]"];
  for (const tag of sections) {
    const idx = text.indexOf(tag);
    if (idx < 0) continue;
    const tail = text.slice(idx + tag.length);
    const stop = tail.search(/\n\[/);
    const block = stop > 0 ? tail.slice(0, stop) : tail;
    const lineRe = /^\s*([A-Za-z0-9_.\-]+)\s*=\s*["']?([^"'\n#]+)["']?/gm;
    let m: RegExpExecArray | null;
    while ((m = lineRe.exec(block)) !== null) {
      out.push({
        name: m[1],
        version: stripRange(m[2].trim()),
        ecosystem: "pip",
        manifest: rel,
        scope: tag === "[dev-packages]" ? "dev" : "direct",
      });
      added++;
    }
  }
  return added;
}

function readGoMod(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  // require ( foo v1.2.3 \n bar v0.1.0 ) | require foo v1.2.3
  const blockRe = /require\s*\(([\s\S]*?)\)/g;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(text)) !== null) {
    for (const line of m[1].split("\n")) {
      const lm = line.trim().match(/^([\w.\-/]+)\s+(v[\d.\-+\w]+)/);
      if (lm) {
        out.push({ name: lm[1], version: lm[2], ecosystem: "go", manifest: rel, scope: "direct" });
        added++;
      }
    }
  }
  const singleRe = /^require\s+([\w.\-/]+)\s+(v[\d.\-+\w]+)/gm;
  while ((m = singleRe.exec(text)) !== null) {
    out.push({ name: m[1], version: m[2], ecosystem: "go", manifest: rel, scope: "direct" });
    added++;
  }
  return added;
}

function readCargoToml(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  const tags = ["[dependencies]", "[dev-dependencies]", "[build-dependencies]"];
  for (const tag of tags) {
    const idx = text.indexOf(tag);
    if (idx < 0) continue;
    const tail = text.slice(idx + tag.length);
    const stop = tail.search(/\n\[/);
    const block = stop > 0 ? tail.slice(0, stop) : tail;
    const lineRe = /^\s*([A-Za-z0-9_.\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*["']([^"']+)["']|["']([^"'\n]+)["'])/gm;
    let m: RegExpExecArray | null;
    while ((m = lineRe.exec(block)) !== null) {
      out.push({
        name: m[1],
        version: m[2] ?? m[3],
        ecosystem: "cargo",
        manifest: rel,
        scope: tag === "[dev-dependencies]" ? "dev" : "direct",
      });
      added++;
    }
  }
  return added;
}

function readPomXml(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  const re = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const block = m[1];
    const g = block.match(/<groupId>([^<]+)<\/groupId>/);
    const a = block.match(/<artifactId>([^<]+)<\/artifactId>/);
    const v = block.match(/<version>([^<]+)<\/version>/);
    if (g && a) {
      out.push({
        name: `${g[1]}:${a[1]}`,
        version: v?.[1],
        ecosystem: "maven",
        manifest: rel,
        scope: "direct",
      });
      added++;
    }
  }
  return added;
}

function readGradle(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  // implementation 'group:artifact:version' or "group:artifact:version"
  const re = /\b(?:implementation|api|compile|testImplementation|runtimeOnly)\s*\(?[ \t]*['"]([^:'"\s]+):([^:'"\s]+):([^'"\s]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({
      name: `${m[1]}:${m[2]}`,
      version: m[3],
      ecosystem: "gradle",
      manifest: rel,
      scope: "direct",
    });
    added++;
  }
  return added;
}

function readGemfile(abs: string, rel: string, out: DependencyPackage[]): number {
  const text = readFileSync(abs, "utf8");
  let added = 0;
  // gem 'name', '~> 1.2.3'
  const re = /^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({
      name: m[1],
      version: stripRange(m[2] ?? ""),
      ecosystem: "ruby",
      manifest: rel,
      scope: "direct",
    });
    added++;
  }
  return added;
}

function readComposerJson(abs: string, rel: string, out: DependencyPackage[]): number {
  const obj = JSON.parse(readFileSync(abs, "utf8"));
  let added = 0;
  for (const [key, scope] of [
    ["require", "direct"],
    ["require-dev", "dev"],
  ] as const) {
    const sec = (obj?.[key] ?? {}) as Record<string, string>;
    for (const [name, version] of Object.entries(sec)) {
      out.push({
        name,
        version: stripRange(version),
        ecosystem: "php",
        manifest: rel,
        scope,
      });
      added++;
    }
  }
  return added;
}

// ─── helpers ────────────────────────────────────────────────────────────────

function stripRange(v: string): string | undefined {
  const cleaned = v.replace(/^[\^~><=*\s]+/, "").trim();
  return cleaned || undefined;
}

function dedupe(pkgs: DependencyPackage[]): DependencyPackage[] {
  const seen = new Map<string, DependencyPackage>();
  for (const p of pkgs) {
    const key = `${p.ecosystem}::${p.name}::${p.version ?? ""}::${p.manifest}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  return [...seen.values()];
}

/** Languages we can derive from observed ecosystems (used to prune scanners). */
export function languagesFromEcosystems(ecos: Ecosystem[]): string[] {
  const out = new Set<string>();
  for (const e of ecos) {
    if (e === "npm") {
      out.add("javascript");
      out.add("typescript");
    } else if (e === "pip") out.add("python");
    else if (e === "go") out.add("go");
    else if (e === "cargo") out.add("rust");
    else if (e === "maven" || e === "gradle") out.add("java");
    else if (e === "ruby") out.add("ruby");
    else if (e === "php") out.add("php");
  }
  return Array.from(out);
}

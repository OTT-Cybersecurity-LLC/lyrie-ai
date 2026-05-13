import { promises as fs, readFileSync, statSync } from "node:fs";
import { homedir, hostname, loadavg, platform, totalmem, freemem, cpus, networkInterfaces, uptime } from "node:os";
import { join, resolve } from "node:path";

import type { SkillExecutionResult, SkillManager } from "./skill-manager";
import type { ShieldGuardLike } from "../engine/shield-guard";
import { ShieldGuard } from "../engine/shield-guard";
import { WebSearch } from "../tools/web/web-search";
import { ThreatIntelClient } from "../pentest/threat-intel/client";
import { safeFetch, isAllowedHost } from "../security/url-guard";

export interface BuiltInExecutorConfig {
  /** Inject a ShieldGuard (defaults to ShieldGuard.fallback()). */
  shield?: ShieldGuardLike;
  /** Inject a WebSearch instance (defaults to new WebSearch() reading env). */
  brave?: WebSearch;
  /** Inject a ThreatIntelClient (defaults to new client). */
  threatClient?: ThreatIntelClient;
  /** Sandbox root for file-management (default: process.env.LYRIE_FS_ROOT or homedir/.lyrie/sandbox). */
  fsRoot?: string;
}

function ok(output: any): SkillExecutionResult {
  return { success: true, output, duration: 0 };
}
function fail(error: string): SkillExecutionResult {
  return { success: false, output: null, duration: 0, error };
}

function pickStr(ctx: any, ...keys: string[]): string {
  for (const k of keys) {
    const v = ctx?.[k];
    if (typeof v === "string" && v.trim()) return v;
  }
  return "";
}

// ─── web-search ──────────────────────────────────────────────────────────────

function makeWebSearchExecutor(brave: WebSearch) {
  return async (ctx: any): Promise<SkillExecutionResult> => {
    const query = pickStr(ctx, "query", "q", "input");
    if (!query) return fail("web-search: missing `query`");
    try {
      const results = await brave.search(query, { count: ctx?.count ?? 5 });
      return ok({ engine: "brave", query, count: results.length, results });
    } catch (err: any) {
      // DDG fallback: scrape duckduckgo HTML. Best-effort; respects safeFetch.
      try {
        const url = `https://duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
        const res = await safeFetch(url, { headers: { "User-Agent": "Lyrie/1.0" } }, { timeoutMs: 10_000 });
        const html = await res.text();
        const matches = [...html.matchAll(/<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([^<]+)<\/a>/g)];
        const results = matches.slice(0, ctx?.count ?? 5).map((m) => ({
          title: m[2],
          url: m[1],
          snippet: "",
        }));
        return ok({ engine: "duckduckgo", query, count: results.length, results, note: `Brave failed: ${err.message}` });
      } catch (e2: any) {
        return fail(`web-search: brave=${err.message} ddg=${e2.message}`);
      }
    }
  };
}

// ─── code-execution ──────────────────────────────────────────────────────────

function makeCodeExecutionExecutor(fsRoot: string) {
  return async (ctx: any): Promise<SkillExecutionResult> => {
    const code = pickStr(ctx, "code", "source");
    const language = pickStr(ctx, "language", "lang") || "py";
    if (!code) return fail("code-execution: missing `code`");
    const ext: Record<string, string> = { py: "py", python: "py", js: "js", ts: "ts", sh: "sh", bash: "sh" };
    const e = ext[language.toLowerCase()] ?? "txt";
    const filename = `lyrie-skill-${Date.now()}.${e}`;
    const target = join(fsRoot, filename);
    await fs.mkdir(fsRoot, { recursive: true });
    await fs.writeFile(target, code, "utf8");
    return ok({
      action: "wrote",
      file: target,
      language: e,
      bytes: Buffer.byteLength(code, "utf8"),
      note: "Code written to sandbox. Use the `exec` tool to run it (this skill never spawns processes itself).",
    });
  };
}

// ─── file-management ─────────────────────────────────────────────────────────

function makeFileManagementExecutor(fsRoot: string) {
  const guard = (target: string): string => {
    const abs = resolve(target.startsWith("/") || target.startsWith("~") ? target : join(fsRoot, target));
    if (!abs.startsWith(resolve(fsRoot))) {
      throw new Error(`file-management: path escapes sandbox (${abs})`);
    }
    return abs;
  };
  return async (ctx: any): Promise<SkillExecutionResult> => {
    const op: string = pickStr(ctx, "op", "operation", "action") || "read";
    const path: string = pickStr(ctx, "path", "file", "target");
    if (!path) return fail("file-management: missing `path`");
    try {
      const abs = guard(path);
      switch (op) {
        case "read":
          return ok({ op, path: abs, content: readFileSync(abs, "utf8") });
        case "write": {
          const data = String(ctx?.content ?? "");
          await fs.mkdir(resolve(abs, ".."), { recursive: true });
          await fs.writeFile(abs, data, "utf8");
          return ok({ op, path: abs, bytes: Buffer.byteLength(data, "utf8") });
        }
        case "list":
        case "ls": {
          const entries = await fs.readdir(abs, { withFileTypes: true });
          return ok({
            op,
            path: abs,
            entries: entries.map((e) => ({ name: e.name, type: e.isDirectory() ? "dir" : "file" })),
          });
        }
        case "stat": {
          const s = statSync(abs);
          return ok({ op, path: abs, size: s.size, isFile: s.isFile(), isDir: s.isDirectory(), mtime: s.mtime });
        }
        case "delete":
        case "rm":
          await fs.unlink(abs);
          return ok({ op, path: abs, deleted: true });
        default:
          return fail(`file-management: unsupported op '${op}'`);
      }
    } catch (err: any) {
      return fail(`file-management(${op}): ${err.message}`);
    }
  };
}

// ─── threat-scan ─────────────────────────────────────────────────────────────

function makeThreatScanExecutor(shield: ShieldGuardLike) {
  return async (ctx: any): Promise<SkillExecutionResult> => {
    const target = pickStr(ctx, "target", "url", "input");
    if (!target) return fail("threat-scan: missing `target`");

    const verdicts: Record<string, unknown> = {};
    // 1) Shield content scan
    verdicts.shield = shield.scanRecalled(target);

    // 2) URL HEAD probe (only if target looks like a URL)
    if (/^https?:\/\//i.test(target)) {
      try {
        if (!isAllowedHost(target)) {
          verdicts.url = { reachable: false, reason: "blocked by url-guard (private/loopback)" };
        } else {
          const res = await safeFetch(target, { method: "HEAD" }, { timeoutMs: 8_000 });
          verdicts.url = {
            reachable: true,
            status: res.status,
            contentType: res.headers.get("content-type") ?? "",
            server: res.headers.get("server") ?? "",
          };
        }
      } catch (err: any) {
        verdicts.url = { reachable: false, reason: err.message };
      }
    }

    return ok({ target, verdicts });
  };
}

// ─── vulnerability-check ─────────────────────────────────────────────────────

function makeVulnCheckExecutor(client: ThreatIntelClient) {
  return async (ctx: any): Promise<SkillExecutionResult> => {
    const packages: Array<{ name: string; version?: string; ecosystem?: string }> = ctx?.packages ?? [];
    if (!Array.isArray(packages) || packages.length === 0) {
      return fail("vulnerability-check: missing `packages: Array<{name, version, ecosystem}>`");
    }
    try {
      const matches = await client.matchDependencies(
        packages.map((p) => ({
          name: p.name,
          version: p.version ?? "*",
          ecosystem: (p.ecosystem ?? "npm") as any,
          manifest: "package.json",
        })),
      );
      const kev = matches.filter((m) => m.advisory.kev?.inKev).length;
      return ok({
        totalChecked: packages.length,
        matched: matches.length,
        inKev: kev,
        matches: matches.map((m) => ({
          cve: m.advisory.cve,
          severity: m.advisory.severity,
          matchedOn: m.matchedOn,
          inKev: m.advisory.kev?.inKev ?? false,
        })),
      });
    } catch (err: any) {
      return fail(`vulnerability-check: ${err.message}`);
    }
  };
}

// ─── device-protect ──────────────────────────────────────────────────────────

function makeDeviceProtectExecutor(shield: ShieldGuardLike) {
  return async (_ctx: any): Promise<SkillExecutionResult> => {
    const sample = "test\nimport os\nos.system('echo lyrie')\n";
    const verdict = shield.scanRecalled(sample);
    return ok({
      platform: platform(),
      hostname: hostname(),
      shieldEngineDetected: !!verdict,
      shieldRoundtrip: { input: sample.slice(0, 30) + "...", blocked: verdict.blocked, reason: verdict.reason },
      uptimeS: Math.round(uptime()),
      note: "device-protect verifies Shield round-trip and reports OS context. Real-time interception lives in the host runtime (LyrieEngine + ShieldManager).",
    });
  };
}

// ─── system-monitor ──────────────────────────────────────────────────────────

function makeSystemMonitorExecutor() {
  return async (_ctx: any): Promise<SkillExecutionResult> => {
    const cpuList = cpus();
    const totalGB = totalmem() / (1024 ** 3);
    const freeGB = freemem() / (1024 ** 3);
    const ifaces = networkInterfaces();
    const interfaceCount = Object.keys(ifaces).length;
    return ok({
      hostname: hostname(),
      platform: platform(),
      cpu: {
        model: cpuList[0]?.model ?? "unknown",
        cores: cpuList.length,
        loadavg: loadavg(),
      },
      memory: {
        totalGB: Number(totalGB.toFixed(2)),
        freeGB: Number(freeGB.toFixed(2)),
        usedPct: Number((((totalGB - freeGB) / totalGB) * 100).toFixed(1)),
      },
      uptimeS: Math.round(uptime()),
      interfaces: interfaceCount,
    });
  };
}

// ─── public registration helper ──────────────────────────────────────────────

export function registerBuiltInExecutors(
  sm: SkillManager,
  cfg: BuiltInExecutorConfig = {},
): void {
  const shield = cfg.shield ?? ShieldGuard.fallback();
  const brave = cfg.brave ?? new WebSearch();
  const threatClient = cfg.threatClient ?? new ThreatIntelClient({ offline: true });
  const fsRoot =
    cfg.fsRoot ?? process.env.LYRIE_FS_ROOT ?? join(homedir(), ".lyrie", "sandbox");

  sm.registerExecutor("web-search", makeWebSearchExecutor(brave));
  sm.registerExecutor("code-execution", makeCodeExecutionExecutor(fsRoot));
  sm.registerExecutor("file-management", makeFileManagementExecutor(fsRoot));
  sm.registerExecutor("threat-scan", makeThreatScanExecutor(shield));
  sm.registerExecutor("vulnerability-check", makeVulnCheckExecutor(threatClient));
  sm.registerExecutor("device-protect", makeDeviceProtectExecutor(shield));
  sm.registerExecutor("system-monitor", makeSystemMonitorExecutor());
}

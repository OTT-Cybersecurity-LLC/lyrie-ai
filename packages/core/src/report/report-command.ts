/**
 * `lyrie report` command
 *
 * Reads the most recent .sarif file from lyrie-runs/, base64-encodes it,
 * and opens the report viewer in a browser.
 *
 * Usage:
 *   lyrie report              # opens most recent scan
 *   lyrie report --open       # same (alias)
 *   lyrie report --url        # prints URL only, no browser open
 *   lyrie report <path.sarif> # open a specific SARIF file
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, resolve, extname } from "path";

const VIEWER_BASE = "https://lyrie.ai/report";
const VIEWER_LOCAL = "http://localhost:3100/report";

/** Find the most recently modified .sarif file in lyrie-runs/. */
function findLatestSarifFile(cwd: string = process.cwd()): string | null {
  const dir = join(cwd, "lyrie-runs");
  if (!existsSync(dir)) return null;

  const files = readdirSync(dir)
    .filter((f) => extname(f) === ".sarif" || extname(f) === ".json")
    .map((f) => ({ name: f, path: join(dir, f), mtime: statSync(join(dir, f)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);

  return files[0]?.path ?? null;
}

/** Base64-encode a file's contents. */
function b64EncodeFile(filePath: string): string {
  const buf = readFileSync(filePath);
  return Buffer.from(buf).toString("base64");
}

/** Open a URL in the default browser (cross-platform). */
async function openBrowser(url: string): Promise<boolean> {
  const { exec } = await import("child_process");
  const { promisify } = await import("util");
  const execAsync = promisify(exec);

  const cmds: Record<string, string> = {
    darwin: `open "${url}"`,
    linux: `xdg-open "${url}"`,
    win32: `start "" "${url}"`,
  };
  const cmd = cmds[process.platform] ?? `xdg-open "${url}"`;

  try {
    await execAsync(cmd);
    return true;
  } catch {
    return false;
  }
}

export interface ReportCommandOptions {
  /** If true, print URL only — do not open browser. */
  urlOnly?: boolean;
  /** Use localhost viewer instead of lyrie.ai. */
  local?: boolean;
  /** Explicit path to a SARIF file. */
  sarifPath?: string;
  /** Working directory for finding lyrie-runs/. Defaults to process.cwd(). */
  cwd?: string;
}

/**
 * Run the `lyrie report` command.
 * Returns the generated report URL.
 */
export async function runReportCommand(opts: ReportCommandOptions = {}): Promise<string> {
  const { urlOnly = false, local = false, sarifPath: explicitPath, cwd } = opts;

  // Resolve SARIF file
  let sarifPath: string | null = null;

  if (explicitPath) {
    sarifPath = resolve(explicitPath);
    if (!existsSync(sarifPath)) {
      throw new Error(`SARIF file not found: ${sarifPath}`);
    }
  } else {
    sarifPath = findLatestSarifFile(cwd);
    if (!sarifPath) {
      throw new Error(
        "No .sarif files found in lyrie-runs/. Run a scan first: lyrie scan <target>"
      );
    }
  }

  // Encode
  const b64 = b64EncodeFile(sarifPath);
  const base = local ? VIEWER_LOCAL : VIEWER_BASE;
  const url = `${base}?data=${b64}`;

  if (urlOnly) {
    console.log(url);
    return url;
  }

  console.log(`📄 Opening SARIF report: ${sarifPath}`);
  console.log(`🌐 URL: ${url.slice(0, 80)}…`);

  const opened = await openBrowser(url);
  if (!opened) {
    console.log("⚠️  Could not open browser automatically. Copy the URL above.");
  }

  return url;
}

/**
 * Print the "view report" hint after a scan completes.
 * Call this from the scan result handler.
 */
export function printReportHint(): void {
  console.log("\n💡 View report: lyrie report --open\n");
}

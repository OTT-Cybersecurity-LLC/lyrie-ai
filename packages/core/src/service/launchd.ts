/**
 * lyrie service — macOS launchd implementation
 * Manages a user-level LaunchAgent plist in ~/Library/LaunchAgents/
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { execSync, spawnSync } from "child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { IServiceManager, ServiceConfig, ServiceStatus } from "./types";

export class LaunchdService implements IServiceManager {
  private label = "ai.lyrie.daemon";
  private config?: ServiceConfig;

  /** Path to the installed plist */
  get plistPath(): string {
    return join(homedir(), "Library", "LaunchAgents", `${this.label}.plist`);
  }

  /** Default log directory */
  private get defaultLogDir(): string {
    return join(homedir(), ".lyrie", "logs");
  }

  /** Generate plist XML from a ServiceConfig */
  generatePlist(config: ServiceConfig): string {
    const logPath = config.logPath ?? join(this.defaultLogDir, "daemon.log");
    const errorLogPath = logPath.replace(/\.log$/, "-error.log");
    const runAtLoad = config.runAtLoad !== false; // default true
    const keepAlive = config.keepAlive !== false; // default true

    const args = [config.program, ...config.args];
    const argsXml = args
      .map((a) => `    <string>${escapeXml(a)}</string>`)
      .join("\n");

    const envXml = config.env
      ? `  <key>EnvironmentVariables</key>\n  <dict>\n${Object.entries(config.env)
          .map(([k, v]) => `    <key>${escapeXml(k)}</key><string>${escapeXml(v)}</string>`)
          .join("\n")}\n  </dict>\n`
      : "";

    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${escapeXml(config.label)}</string>
  <key>ProgramArguments</key>
  <array>
${argsXml}
  </array>
  <key>RunAtLoad</key>
  <${runAtLoad}/>
  <key>KeepAlive</key>
  <${keepAlive}/>
  <key>StandardOutPath</key>
  <string>${escapeXml(logPath)}</string>
  <key>StandardErrorPath</key>
  <string>${escapeXml(errorLogPath)}</string>
${envXml}</dict>
</plist>
`;
  }

  async install(config: ServiceConfig): Promise<void> {
    this.label = config.label;
    this.config = config;

    // Ensure log directory exists
    const logDir = config.logPath
      ? join(config.logPath, "..").replace(/[^/]+$/, "")
      : this.defaultLogDir;
    if (!existsSync(logDir)) {
      mkdirSync(logDir, { recursive: true });
    }

    // Ensure LaunchAgents dir exists (it always should on macOS but be safe)
    const launchAgentsDir = join(homedir(), "Library", "LaunchAgents");
    if (!existsSync(launchAgentsDir)) {
      mkdirSync(launchAgentsDir, { recursive: true });
    }

    // Write plist
    const plist = this.generatePlist(config);
    writeFileSync(this.plistPath, plist, "utf8");

    // Load the service
    try {
      execSync(`launchctl load "${this.plistPath}"`, { stdio: "pipe" });
    } catch {
      // Already loaded or first-time load — try bootstrap
      execSync(`launchctl bootstrap gui/$(id -u) "${this.plistPath}"`, { stdio: "pipe" });
    }

    const status = await this.status();
    const pid = status.pid ? ` PID: ${status.pid}` : "";
    console.log(`✅ Lyrie daemon installed and running.${pid}`);
  }

  async uninstall(): Promise<void> {
    if (existsSync(this.plistPath)) {
      try {
        execSync(`launchctl unload "${this.plistPath}"`, { stdio: "pipe" });
      } catch {
        try {
          execSync(`launchctl bootout gui/$(id -u) "${this.plistPath}"`, { stdio: "pipe" });
        } catch {
          // Ignore — already unloaded
        }
      }
      unlinkSync(this.plistPath);
    }
    console.log("✅ Lyrie daemon uninstalled.");
  }

  async start(): Promise<void> {
    execSync(`launchctl start "${this.label}"`, { stdio: "pipe" });
    console.log(`✅ Started ${this.label}.`);
  }

  async stop(): Promise<void> {
    execSync(`launchctl stop "${this.label}"`, { stdio: "pipe" });
    console.log(`✅ Stopped ${this.label}.`);
  }

  async restart(): Promise<void> {
    await this.stop();
    await this.start();
  }

  async status(): Promise<ServiceStatus> {
    try {
      const out = execSync(`launchctl list "${this.label}" 2>/dev/null`, {
        stdio: "pipe",
        encoding: "utf8",
      });
      // launchctl list output: PID  Status  Label
      const lines = out.split("\n");
      const dataLine = lines.find((l) => l.includes(this.label));
      if (dataLine) {
        const [pidStr] = dataLine.trim().split(/\s+/);
        const pid = parseInt(pidStr, 10);
        return {
          installed: true,
          running: !isNaN(pid) && pid > 0,
          pid: isNaN(pid) ? undefined : pid > 0 ? pid : undefined,
          label: this.label,
        };
      }
      return { installed: existsSync(this.plistPath), running: false, label: this.label };
    } catch {
      return { installed: existsSync(this.plistPath), running: false, label: this.label };
    }
  }

  async logs(lines = 50): Promise<string> {
    const logPath = this.config?.logPath ?? join(this.defaultLogDir, "daemon.log");
    if (!existsSync(logPath)) return "(no log file yet)";
    const result = spawnSync("tail", ["-n", String(lines), logPath], { encoding: "utf8" });
    return result.stdout ?? "(empty log)";
  }
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

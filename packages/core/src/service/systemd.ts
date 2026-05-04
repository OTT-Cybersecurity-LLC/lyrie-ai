/**
 * lyrie service — Linux systemd user-service implementation
 * Manages ~/.config/systemd/user/lyrie.service
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { execSync, spawnSync } from "child_process";
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { IServiceManager, ServiceConfig, ServiceStatus } from "./types";

export class SystemdService implements IServiceManager {
  private unitName = "lyrie";
  private config?: ServiceConfig;

  /** Path to the user systemd unit directory */
  private get unitDir(): string {
    return join(homedir(), ".config", "systemd", "user");
  }

  /** Path to the installed unit file */
  get unitPath(): string {
    return join(this.unitDir, `${this.unitName}.service`);
  }

  /** Default log path (systemd uses journald, but we keep a log path for parity) */
  private get defaultLogDir(): string {
    return join(homedir(), ".lyrie", "logs");
  }

  /** Generate a systemd user service unit file from ServiceConfig */
  generateUnitFile(config: ServiceConfig): string {
    const execStart = [config.program, ...config.args]
      .map((a) => systemdEscapeArg(a))
      .join(" ");

    const envLines = config.env
      ? Object.entries(config.env)
          .map(([k, v]) => `Environment="${k}=${v}"`)
          .join("\n")
      : "";

    const wantedBy =
      config.runAtLoad !== false ? "\n[Install]\nWantedBy=default.target" : "";

    const restart = config.keepAlive !== false ? "Restart=always\nRestartSec=5" : "Restart=on-failure";

    return `[Unit]
Description=Lyrie AI Daemon (${config.label})
After=network.target

[Service]
Type=simple
ExecStart=${execStart}
${restart}
StandardOutput=append:${config.logPath ?? join(this.defaultLogDir, "daemon.log")}
StandardError=append:${(config.logPath ?? join(this.defaultLogDir, "daemon.log")).replace(/\.log$/, "-error.log")}
${envLines ? envLines + "\n" : ""}SyslogIdentifier=lyrie-daemon
${wantedBy}
`;
  }

  async install(config: ServiceConfig): Promise<void> {
    this.unitName = config.label.replace(/\./g, "-");
    this.config = config;

    // Ensure log directory exists
    const logDir = this.defaultLogDir;
    if (!existsSync(logDir)) {
      mkdirSync(logDir, { recursive: true });
    }

    // Ensure unit dir exists
    if (!existsSync(this.unitDir)) {
      mkdirSync(this.unitDir, { recursive: true });
    }

    // Write unit file
    const unit = this.generateUnitFile(config);
    writeFileSync(this.unitPath, unit, "utf8");

    // Reload daemon & enable + start
    execSync("systemctl --user daemon-reload", { stdio: "pipe" });
    if (config.runAtLoad !== false) {
      execSync(`systemctl --user enable "${this.unitName}.service"`, { stdio: "pipe" });
    }
    execSync(`systemctl --user start "${this.unitName}.service"`, { stdio: "pipe" });

    const status = await this.status();
    const pid = status.pid ? ` PID: ${status.pid}` : "";
    console.log(`✅ Lyrie daemon installed and running.${pid}`);
  }

  async uninstall(): Promise<void> {
    try {
      execSync(`systemctl --user stop "${this.unitName}.service"`, { stdio: "pipe" });
    } catch { /* ignore */ }
    try {
      execSync(`systemctl --user disable "${this.unitName}.service"`, { stdio: "pipe" });
    } catch { /* ignore */ }
    if (existsSync(this.unitPath)) {
      unlinkSync(this.unitPath);
    }
    execSync("systemctl --user daemon-reload", { stdio: "pipe" });
    console.log("✅ Lyrie daemon uninstalled.");
  }

  async start(): Promise<void> {
    execSync(`systemctl --user start "${this.unitName}.service"`, { stdio: "pipe" });
    console.log(`✅ Started ${this.unitName}.`);
  }

  async stop(): Promise<void> {
    execSync(`systemctl --user stop "${this.unitName}.service"`, { stdio: "pipe" });
    console.log(`✅ Stopped ${this.unitName}.`);
  }

  async restart(): Promise<void> {
    execSync(`systemctl --user restart "${this.unitName}.service"`, { stdio: "pipe" });
    console.log(`✅ Restarted ${this.unitName}.`);
  }

  async status(): Promise<ServiceStatus> {
    try {
      const out = execSync(
        `systemctl --user show "${this.unitName}.service" --property=ActiveState,MainPID,LoadState 2>/dev/null`,
        { stdio: "pipe", encoding: "utf8" }
      );
      const props: Record<string, string> = {};
      for (const line of out.split("\n")) {
        const [k, v] = line.split("=");
        if (k && v !== undefined) props[k.trim()] = v.trim();
      }
      const pid = parseInt(props["MainPID"] ?? "0", 10);
      return {
        installed: existsSync(this.unitPath),
        running: props["ActiveState"] === "active",
        pid: pid > 0 ? pid : undefined,
        label: this.unitName,
      };
    } catch {
      return { installed: existsSync(this.unitPath), running: false, label: this.unitName };
    }
  }

  async logs(lines = 50): Promise<string> {
    try {
      const result = spawnSync(
        "journalctl",
        ["--user", "-u", `${this.unitName}.service`, "-n", String(lines), "--no-pager"],
        { encoding: "utf8" }
      );
      return result.stdout ?? "(empty log)";
    } catch {
      return "(journalctl not available)";
    }
  }
}

/**
 * Escape an argument for systemd ExecStart.
 * Only wraps in quotes if it contains spaces; always escapes backslash and double-quote.
 */
function systemdEscapeArg(arg: string): string {
  const escaped = arg.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return escaped.includes(" ") ? `"${escaped}"` : escaped;
}

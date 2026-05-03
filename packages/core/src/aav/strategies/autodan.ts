/**
 * AutoDAN Adversarial Attack Strategy
 * Liu et al. 2023 — https://arxiv.org/abs/2310.04451
 *
 * Black-box genetic algorithm attack. Runs Python script on H200 or H100-NL via SSH.
 * No GPU required; can also run locally if Python 3 is available.
 */

import { execFile, spawn } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface AutoDANConfig {
  /** SSH host for GPU node (H200 preferred, H100-NL fallback) */
  host: string;
  /** SSH port */
  port: number;
  /** SSH key path (optional) */
  identityFile?: string;
  /** Remote path to autodan_attack.py */
  scriptPath: string;
  /** OpenAI-compatible endpoint to query (default: OpenAI) */
  endpoint: string;
  /** API key for the endpoint */
  apiKey: string;
  /** Genetic algorithm generations */
  generations: number;
  /** Population size per generation */
  population: number;
  /** Run locally instead of over SSH */
  local: boolean;
  /** SSH connection timeout in seconds */
  connectTimeout: number;
}

export interface AutoDANResult {
  prompt: string;
  score: number;
  generations: number;
  error?: string;
}

const DEFAULT_CONFIG: AutoDANConfig = {
  host: "210.157.233.86",
  port: 38084,
  scriptPath: "/root/lyrie-gpu/autodan_attack.py",
  endpoint: "https://api.openai.com/v1",
  apiKey: "",
  generations: 20,
  population: 10,
  local: false,
  connectTimeout: 15,
};

export class AutoDANStrategy {
  private config: AutoDANConfig;

  constructor(config: Partial<AutoDANConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Check SSH connectivity to the attack host */
  async isAvailable(): Promise<boolean> {
    if (this.config.local) {
      // Local mode: just check python3 exists
      try {
        const { stdout } = await execFileAsync("python3", ["--version"], { timeout: 5000 });
        return stdout.includes("Python 3") || true;
      } catch {
        return false;
      }
    }

    try {
      const sshArgs = this.buildSshArgs("echo ok");
      const { stdout } = await execFileAsync("ssh", sshArgs, {
        timeout: (this.config.connectTimeout + 2) * 1000,
      });
      return stdout.trim().includes("ok");
    } catch {
      return false;
    }
  }

  /**
   * Run AutoDAN genetic attack against a target behavior.
   * @param targetBehavior - The behavior to bypass safety filters for
   * @returns AutoDANResult with the best jailbreak prompt found
   */
  async attack(targetBehavior: string): Promise<AutoDANResult> {
    const scriptArgs = [
      `--target-behavior`, targetBehavior,
      `--endpoint`, this.config.endpoint,
      `--api-key`, this.config.apiKey,
      `--generations`, String(this.config.generations),
      `--population`, String(this.config.population),
      `--output-json`,
    ];

    try {
      if (this.config.local) {
        return await this.runLocal(scriptArgs);
      }
      return await this.runRemote(scriptArgs);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { prompt: "", score: 0, generations: 0, error: msg };
    }
  }

  private async runLocal(scriptArgs: string[]): Promise<AutoDANResult> {
    const { stdout } = await execFileAsync(
      "python3",
      ["/tmp/autodan_attack.py", ...scriptArgs],
      { timeout: 300_000 }
    );
    const jsonLine = stdout.trim().split("\n").find((l) => l.startsWith("{"));
    if (!jsonLine) throw new Error("No JSON in local output");
    return JSON.parse(jsonLine) as AutoDANResult;
  }

  private async runRemote(scriptArgs: string[]): Promise<AutoDANResult> {
    const remoteCmd = [
      `python3 ${this.config.scriptPath}`,
      ...scriptArgs.map((a) => (a.includes(" ") ? JSON.stringify(a) : a)),
    ].join(" ");

    const sshArgs = this.buildSshArgs(remoteCmd);
    const { stdout, stderr } = await execFileAsync("ssh", sshArgs, {
      timeout: 300_000,
    });

    const jsonLine = stdout.trim().split("\n").find((l) => l.startsWith("{"));
    if (!jsonLine) {
      throw new Error(`No JSON in stdout. stderr: ${stderr.slice(-500)}`);
    }
    return JSON.parse(jsonLine) as AutoDANResult;
  }

  private buildSshArgs(remoteCmd: string): string[] {
    const args: string[] = [
      "-o", "StrictHostKeyChecking=no",
      "-o", `ConnectTimeout=${this.config.connectTimeout}`,
      "-p", String(this.config.port),
    ];
    if (this.config.identityFile) {
      args.push("-i", this.config.identityFile);
    }
    args.push(`root@${this.config.host}`, remoteCmd);
    return args;
  }
}

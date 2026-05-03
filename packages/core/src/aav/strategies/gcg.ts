/**
 * GCG (Greedy Coordinate Gradient) Adversarial Suffix Strategy
 * Zou et al. 2023 — https://arxiv.org/abs/2307.15043
 *
 * White-box gradient-based attack. Runs Python script on H200 GPU via SSH.
 */

import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface GCGConfig {
  /** SSH host for the H200 GPU */
  host: string;
  /** SSH port */
  port: number;
  /** SSH key path (optional, uses default if omitted) */
  identityFile?: string;
  /** Remote path to gcg_attack.py */
  scriptPath: string;
  /** HuggingFace model to attack (default: gpt2) */
  model: string;
  /** Number of GCG optimization steps */
  steps: number;
  /** SSH connection timeout in seconds */
  connectTimeout: number;
}

export interface GCGResult {
  suffix: string;
  loss: number;
  steps: number;
  model: string;
  device: string;
  error?: string;
}

const DEFAULT_CONFIG: GCGConfig = {
  host: "210.157.233.86",
  port: 38084,
  scriptPath: "/root/lyrie-gpu/gcg_attack.py",
  model: "gpt2",
  steps: 500,
  connectTimeout: 15,
};

export class GCGStrategy {
  private config: GCGConfig;

  constructor(config: Partial<GCGConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Check if the H200 GPU host is reachable */
  async isAvailable(): Promise<boolean> {
    try {
      const sshArgs = this.buildSshArgs("echo ok");
      const { stdout } = await execFileAsync("ssh", sshArgs, { timeout: (this.config.connectTimeout + 2) * 1000 });
      return stdout.trim().includes("ok");
    } catch {
      return false;
    }
  }

  /**
   * Run GCG adversarial suffix generation against a target behavior.
   * @param targetBehavior - The harmful behavior string to optimize a suffix for
   * @returns GCGResult with the best suffix found
   */
  async attack(targetBehavior: string): Promise<GCGResult> {
    const cmd = [
      `python3 ${this.config.scriptPath}`,
      `--target-behavior ${JSON.stringify(targetBehavior)}`,
      `--model ${this.config.model}`,
      `--steps ${this.config.steps}`,
      "--output-json",
    ].join(" ");

    const sshArgs = this.buildSshArgs(cmd);

    try {
      const { stdout, stderr } = await execFileAsync("ssh", sshArgs, {
        timeout: 600_000, // 10 min max
      });

      // stderr has progress logs, stdout has JSON
      const jsonLine = stdout.trim().split("\n").find((l) => l.startsWith("{"));
      if (!jsonLine) {
        throw new Error(`No JSON in stdout. stderr: ${stderr.slice(-500)}`);
      }
      return JSON.parse(jsonLine) as GCGResult;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        suffix: "",
        loss: 9999,
        steps: 0,
        model: this.config.model,
        device: "unknown",
        error: msg,
      };
    }
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

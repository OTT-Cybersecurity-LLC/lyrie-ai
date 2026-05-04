/**
 * process-manager.ts — Background session management for LyrieExec.
 *
 * Manages long-running commands that outlive a single agent turn.
 * Sessions survive across turns; the agent polls, tails, or kills them.
 *
 * PTY support: if pty=true we spawn through /dev/ptmx via node:child_process
 * with { detached: false, stdio: 'pipe' } + a thin PTY wrapper. On macOS/Linux
 * we use `script -q /dev/null <cmd>` to allocate a real TTY when node-pty
 * is not installed. Falls back to a plain pipe on unsupported platforms.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { platform } from "node:os";

// ─── Constants ────────────────────────────────────────────────────────────────

/** Max bytes kept in the ring buffer per session. */
const MAX_OUTPUT_BYTES = 1_000_000; // 1 MB

/** Max chars returned by a single log/poll call before truncation. */
export const MAX_OUTPUT_CHARS = 10_000;

/** How long a completed session is kept before GC (ms). */
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 min

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExecOptions {
  workdir?: string;
  timeout?: number; // ms
  pty?: boolean;
  env?: Record<string, string>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  truncated: boolean;
  truncatedLines?: number;
}

export interface PollResult {
  done: boolean;
  output: string;
  exitCode?: number;
  truncated: boolean;
  truncatedLines?: number;
}

export type SessionStatus = "running" | "done" | "killed" | "error" | "timeout";

export interface SessionInfo {
  sessionId: string;
  command: string;
  status: SessionStatus;
  startedAt: Date;
  endedAt?: Date;
  exitCode?: number;
  pid?: number;
  linesBuffered: number;
}

// ─── Internal session ─────────────────────────────────────────────────────────

interface Session {
  id: string;
  command: string;
  process: ChildProcess;
  outputBuffer: string; // rolling ring buffer
  status: SessionStatus;
  startedAt: Date;
  endedAt?: Date;
  exitCode?: number;
  pid?: number;
  emitter: EventEmitter;
  gcTimer?: ReturnType<typeof setTimeout>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function truncate(text: string): { text: string; truncated: boolean; truncatedLines?: number } {
  if (text.length <= MAX_OUTPUT_CHARS) return { text, truncated: false };

  const tail = text.slice(-MAX_OUTPUT_CHARS);
  const totalLines = text.split("\n").length;
  const tailLines = tail.split("\n").length;
  const truncatedLines = totalLines - tailLines;

  return {
    text: `... (${truncatedLines} lines truncated)\n${tail}`,
    truncated: true,
    truncatedLines,
  };
}

function buildCommand(command: string, pty: boolean): { cmd: string; args: string[] } {
  if (!pty) {
    return { cmd: "sh", args: ["-c", command] };
  }
  // Allocate a real PTY via `script` on macOS/Linux
  if (platform() === "darwin") {
    return { cmd: "script", args: ["-q", "/dev/null", "sh", "-c", command] };
  }
  if (platform() === "linux") {
    return { cmd: "script", args: ["-q", "-e", "-c", command, "/dev/null"] };
  }
  // Fallback — no PTY available on this platform
  return { cmd: "sh", args: ["-c", command] };
}

// ─── ProcessManager ───────────────────────────────────────────────────────────

export class ProcessManager {
  private sessions: Map<string, Session> = new Map();

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Run a command synchronously (within the turn).
   * Buffers stdout+stderr, applies truncation, respects timeout.
   */
  async run(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const { workdir, timeout, pty = false, env } = options;
    const { cmd, args } = buildCommand(command, pty);

    return new Promise((resolve, reject) => {
      let stdout = "";
      let stderr = "";

      const child = spawn(cmd, args, {
        cwd: workdir,
        env: { ...process.env, ...(env ?? {}) },
        stdio: "pipe",
      });

      child.stdout?.on("data", (d: Buffer) => {
        stdout += d.toString();
        if (stdout.length > MAX_OUTPUT_BYTES) stdout = stdout.slice(-MAX_OUTPUT_BYTES);
      });
      child.stderr?.on("data", (d: Buffer) => {
        stderr += d.toString();
        if (stderr.length > MAX_OUTPUT_BYTES) stderr = stderr.slice(-MAX_OUTPUT_BYTES);
      });

      let timer: ReturnType<typeof setTimeout> | undefined;
      if (timeout) {
        timer = setTimeout(() => {
          child.kill("SIGKILL");
          const combined = stdout + stderr;
          const { text, truncated, truncatedLines } = truncate(combined);
          resolve({ stdout: text, stderr: "", exitCode: -1, truncated, truncatedLines });
        }, timeout);
      }

      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      child.on("close", (code) => {
        clearTimeout(timer);
        const combined = (stdout + (stderr ? `\n--- stderr ---\n${stderr}` : "")).trim();
        const { text, truncated, truncatedLines } = truncate(combined);
        resolve({ stdout: text, stderr: "", exitCode: code ?? 0, truncated, truncatedLines });
      });
    });
  }

  /**
   * Spawn a command in the background.
   * Returns a sessionId immediately; use poll/log/kill to interact.
   */
  async background(command: string, options: ExecOptions = {}): Promise<string> {
    const { workdir, timeout, pty = false, env } = options;
    const sessionId = randomUUID();
    const { cmd, args } = buildCommand(command, pty);

    const emitter = new EventEmitter();
    const child = spawn(cmd, args, {
      cwd: workdir,
      env: { ...process.env, ...(env ?? {}) },
      stdio: "pipe",
      detached: false,
    });

    const session: Session = {
      id: sessionId,
      command,
      process: child,
      outputBuffer: "",
      status: "running",
      startedAt: new Date(),
      pid: child.pid,
      emitter,
    };
    this.sessions.set(sessionId, session);

    const append = (data: Buffer) => {
      session.outputBuffer += data.toString();
      if (session.outputBuffer.length > MAX_OUTPUT_BYTES) {
        session.outputBuffer = session.outputBuffer.slice(-MAX_OUTPUT_BYTES);
      }
      emitter.emit("data");
    };

    child.stdout?.on("data", append);
    child.stderr?.on("data", append);

    let timer: ReturnType<typeof setTimeout> | undefined;
    if (timeout) {
      timer = setTimeout(() => {
        if (session.status === "running") {
          child.kill("SIGKILL");
          session.status = "timeout";
          session.endedAt = new Date();
          emitter.emit("done");
          this._scheduleGC(session);
        }
      }, timeout);
    }

    child.on("error", (err) => {
      clearTimeout(timer);
      session.status = "error";
      session.outputBuffer += `\n[error: ${err.message}]`;
      session.endedAt = new Date();
      emitter.emit("done");
      this._scheduleGC(session);
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      if (session.status === "running") {
        session.status = code === 0 ? "done" : "error";
        session.exitCode = code ?? 0;
        session.endedAt = new Date();
        emitter.emit("done");
        this._scheduleGC(session);
      }
    });

    return sessionId;
  }

  /**
   * Wait for a background session to complete (or timeout).
   * Returns current output and done status.
   */
  async poll(sessionId: string, timeoutMs = 30_000): Promise<PollResult> {
    const session = this._require(sessionId);

    if (session.status !== "running") {
      const { text, truncated, truncatedLines } = truncate(session.outputBuffer);
      return {
        done: true,
        output: text,
        exitCode: session.exitCode,
        truncated,
        truncatedLines,
      };
    }

    await new Promise<void>((resolve) => {
      const onDone = () => {
        clearTimeout(t);
        resolve();
      };
      const t = setTimeout(() => {
        session.emitter.off("done", onDone);
        resolve();
      }, timeoutMs);
      session.emitter.once("done", onDone);
    });

    const { text, truncated, truncatedLines } = truncate(session.outputBuffer);
    return {
      done: session.status !== "running",
      output: text,
      exitCode: session.exitCode,
      truncated,
      truncatedLines,
    };
  }

  /**
   * Return buffered output for a session (supports offset pagination).
   */
  async log(sessionId: string, limit?: number, offset?: number): Promise<string> {
    const session = this._require(sessionId);
    const lines = session.outputBuffer.split("\n");
    const start = offset ?? 0;
    const end = limit !== undefined ? start + limit : undefined;
    const slice = lines.slice(start, end).join("\n");
    const { text } = truncate(slice);
    return text;
  }

  /**
   * Kill a running session.
   */
  async kill(sessionId: string): Promise<void> {
    const session = this._require(sessionId);
    if (session.status !== "running") return;
    session.process.kill("SIGKILL");
    session.status = "killed";
    session.endedAt = new Date();
    session.emitter.emit("done");
    this._scheduleGC(session);
  }

  /**
   * List all tracked sessions.
   */
  list(): SessionInfo[] {
    return Array.from(this.sessions.values()).map((s) => ({
      sessionId: s.id,
      command: s.command,
      status: s.status,
      startedAt: s.startedAt,
      endedAt: s.endedAt,
      exitCode: s.exitCode,
      pid: s.pid,
      linesBuffered: s.outputBuffer.split("\n").length,
    }));
  }

  // ── Private ─────────────────────────────────────────────────────────────────

  private _require(sessionId: string): Session {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Unknown session: ${sessionId}`);
    return session;
  }

  private _scheduleGC(session: Session): void {
    if (session.gcTimer) return;
    session.gcTimer = setTimeout(() => {
      this.sessions.delete(session.id);
    }, SESSION_TTL_MS);
  }
}

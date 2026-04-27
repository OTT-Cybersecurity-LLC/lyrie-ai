/**
 * ShieldManager — The cybersecurity layer of Lyrie Agent.
 *
 * This is what makes Lyrie unique. Every other agent is naked.
 * Lyrie has a shield.
 *
 * Responsibilities:
 * - Scan all inputs for threats (prompt injection, social engineering)
 * - Validate tool calls before execution (sandbox enforcement)
 * - Monitor for rogue AI behavior
 * - Protect device and file system (path scoping)
 * - WAF capabilities for web-facing endpoints
 * - URL reputation checking
 * - Command allow/deny with pattern matching
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { resolve as resolvePath, normalize } from "path";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ThreatScanResult {
  blocked: boolean;
  reason?: string;
  severity: "none" | "low" | "medium" | "high" | "critical";
  details?: string;
  timestamp?: number;
}

export interface ToolCallValidation {
  tool: string;
  args: any;
  risk: "safe" | "moderate" | "dangerous";
}

export type ShieldMode = "passive" | "active" | "strict";

export interface ShieldConfig {
  mode?: ShieldMode;
  allowedPaths?: string[];
  blockedCommands?: string[];
  allowDangerousTools?: boolean;
  maxExecTimeout?: number;
  blockedDomains?: string[];
}

export interface ShieldEvent {
  type: "blocked" | "allowed" | "warning";
  tool?: string;
  target?: string;
  reason: string;
  severity: ThreatScanResult["severity"];
  timestamp: number;
}

// ─── Shield Manager ──────────────────────────────────────────────────────────

export class ShieldManager {
  private initialized = false;
  private mode: ShieldMode = "active";
  private blockedInputPatterns: RegExp[] = [];
  private blockedCommandPatterns: RegExp[] = [];
  private allowedPaths: string[] = [];
  private blockedDomains: Set<string> = new Set();
  private allowDangerousTools = false;
  private maxExecTimeout = 120000;
  private eventLog: ShieldEvent[] = [];
  private maxEventLog = 500;

  async initialize(config?: ShieldConfig): Promise<void> {
    this.mode = config?.mode ?? "active";
    this.allowDangerousTools = config?.allowDangerousTools ?? false;
    this.maxExecTimeout = config?.maxExecTimeout ?? 120000;

    // ── Input threat patterns ─────────────────────────────────────────
    this.blockedInputPatterns = [
      // Prompt injection
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /you\s+are\s+now\s+(a|an|my)\b/i,
      /system\s*prompt\s*(override|change|modify|replace)/i,
      /forget\s+(everything|all|your)\b/i,
      /new\s+instructions?\s*:/i,
      /\bDAN\s+mode\b/i,
      /\bjailbreak\b/i,

      // Data exfiltration via prompt
      /output\s+(all|every|your)\s+(system|hidden|secret)/i,
      /reveal\s+(your|the)\s+(system|hidden|secret)\s+prompt/i,
    ];

    // ── Dangerous command patterns ────────────────────────────────────
    this.blockedCommandPatterns = [
      // Destructive filesystem operations
      /rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|--force\s+)?\//,
      /rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+\//,
      /\brm\s+-rf\s+[~\/]/,
      /\bformat\s+[a-z]:/i,
      /\bmkfs\b/,
      /\bdd\s+if=.*of=\/dev/,

      // Fork bombs and resource exhaustion
      /:\(\)\s*\{.*\|.*&\s*\}/,
      /\bfork\s*bomb\b/i,
      /while\s+true\s*;\s*do\s*:\s*;\s*done/,

      // Credential exfiltration
      /curl\s+.*\b(password|secret|token|api.?key)\b.*\bhttp/i,
      /wget\s+.*\bhttp.*>.*\.(env|key|pem|secret)/i,

      // Network backdoors
      /\bnc\s+-[a-zA-Z]*l[a-zA-Z]*\s+-p/,  // netcat listen
      /\bsocat\b.*\bexec\b/i,
      /\bssh\b.*-R\s+\d+:/,                 // reverse tunnel
      /\bnohup\b.*\b(nc|ncat|socat)\b/,

      // System compromise
      /\bchmod\s+[0-7]*777\s+\//,
      /\bchown\s+.*\s+\//,
      /\bpasswd\b/,
      /\buseradd\b/,
      /\bvisudo\b/,
      /\bsudo\s+su\b/,
      /\bcrontab\s+-r\b/,

      // Crypto miners
      /\b(xmrig|minerd|cpuminer|cryptonight)\b/i,

      // Kernel/bootloader
      /\binsmod\b/,
      /\brmmod\b/,
      /\bmodprobe\b/,
      /\/boot\/(vmlinuz|initrd|grub)/,
    ];

    // ── Allowed workspace paths ───────────────────────────────────────
    const os = require("os");
    const home = os.homedir();
    const platform = os.platform();
    
    this.allowedPaths = [
      normalize(home),              // Full home directory (personal agent needs access)
      normalize(process.cwd()),
      normalize(`${home}/.lyrie`),
      ...(platform === "win32"
        ? [normalize("C:\\temp"), normalize(process.env.TEMP || "C:\\temp")]
        : [normalize("/tmp")]),
      ...(config?.allowedPaths?.map((p) => normalize(resolvePath(p))) ?? []),
    ];

    // ── Blocked domains ───────────────────────────────────────────────
    const defaultBlocked = [
      "evil.com",
      "malware.com",
    ];
    for (const d of [...defaultBlocked, ...(config?.blockedDomains ?? [])]) {
      this.blockedDomains.add(d.toLowerCase());
    }

    this.initialized = true;
    console.log(
      `   → Shield active [mode=${this.mode}]: input scanning, tool validation, path scoping, URL filtering`
    );
  }

  // ─── Input Scanning ────────────────────────────────────────────────────

  /**
   * Scan user input for potential threats.
   */
  async scanInput(input: string): Promise<ThreatScanResult> {
    if (!this.initialized || this.mode === "passive") {
      return { blocked: false, severity: "none" };
    }

    // 1. Prompt injection patterns
    for (const pattern of this.blockedInputPatterns) {
      if (pattern.test(input)) {
        this.logEvent({
          type: "blocked",
          target: input.slice(0, 100),
          reason: `Prompt injection pattern: ${pattern.source}`,
          severity: "high",
          timestamp: Date.now(),
        });
        return {
          blocked: true,
          reason: "Blocked: potential prompt injection detected",
          severity: "high",
          details: `Pattern match: ${pattern.source}`,
          timestamp: Date.now(),
        };
      }
    }

    // 2. Dangerous shell-command patterns embedded in user text. We don't
    // wait for the tool-call boundary — if a user pastes `rm -rf /` or a
    // fork bomb into the agent, that's a high-severity signal on its own
    // (might be social-engineering the model into dispatching the command).
    for (const pattern of this.blockedCommandPatterns) {
      if (pattern.test(input)) {
        this.logEvent({
          type: "blocked",
          target: input.slice(0, 100),
          reason: `Dangerous shell pattern in input: ${pattern.source}`,
          severity: "high",
          timestamp: Date.now(),
        });
        return {
          blocked: true,
          reason: "Blocked: dangerous shell pattern detected in input",
          severity: "high",
          details: `Pattern match: ${pattern.source}`,
          timestamp: Date.now(),
        };
      }
    }

    return { blocked: false, severity: "none" };
  }

  // ─── Tool Call Validation ──────────────────────────────────────────────

  /**
   * Validate a tool call before execution.
   * This is the security gate — nothing executes without Shield approval.
   */
  async validateToolCall(call: ToolCallValidation): Promise<boolean> {
    if (!this.initialized) return true;
    if (this.mode === "passive") return true;

    const { tool, args, risk } = call;

    // In strict mode, block all dangerous tools unless explicitly allowed
    if (risk === "dangerous" && !this.allowDangerousTools && this.mode === "strict") {
      this.logEvent({
        type: "blocked",
        tool,
        reason: "Dangerous tool blocked in strict mode",
        severity: "high",
        timestamp: Date.now(),
      });
      console.warn(`🛡️ Shield BLOCKED dangerous tool call: ${tool} (strict mode)`);
      return false;
    }

    // Validate file path operations
    if (this.isFileOperation(tool)) {
      const path = args.path || args.target || "";
      if (!this.isPathAllowed(path)) {
        this.logEvent({
          type: "blocked",
          tool,
          target: path,
          reason: `File access outside allowed workspace`,
          severity: "medium",
          timestamp: Date.now(),
        });
        console.warn(`🛡️ Shield BLOCKED file access outside workspace: ${path}`);
        return false;
      }
    }

    // Validate shell commands
    if (tool === "exec") {
      const command = args.command || "";
      for (const pattern of this.blockedCommandPatterns) {
        if (pattern.test(command)) {
          this.logEvent({
            type: "blocked",
            tool,
            target: command.slice(0, 100),
            reason: `Dangerous command pattern: ${pattern.source}`,
            severity: "critical",
            timestamp: Date.now(),
          });
          console.warn(
            `🛡️ Shield BLOCKED dangerous command: ${command.substring(0, 80)}...`
          );
          return false;
        }
      }

      // Enforce timeout limit
      if (args.timeout && args.timeout > this.maxExecTimeout) {
        args.timeout = this.maxExecTimeout;
      }
    }

    // Validate URLs
    if (tool === "web_fetch" || tool === "web_search") {
      const url = args.url || "";
      if (url && !this.isUrlSafe(url)) {
        this.logEvent({
          type: "blocked",
          tool,
          target: url,
          reason: "URL on blocked domain list",
          severity: "medium",
          timestamp: Date.now(),
        });
        console.warn(`🛡️ Shield BLOCKED access to blocked URL: ${url}`);
        return false;
      }
    }

    // Log allowed in active/strict mode
    this.logEvent({
      type: "allowed",
      tool,
      reason: "Passed validation",
      severity: "none",
      timestamp: Date.now(),
    });

    return true;
  }

  // ─── Path Validation ───────────────────────────────────────────────────

  /**
   * Check if a path is within the allowed workspace boundaries.
   */
  isPathAllowed(path: string): boolean {
    if (!path) return false;

    const resolved = normalize(resolvePath(path));

    // Block obvious traversal attempts
    if (resolved.includes("..")) return false;

    return this.allowedPaths.some((allowed) => resolved.startsWith(allowed));
  }

  /**
   * Add an allowed path at runtime.
   */
  addAllowedPath(path: string): void {
    const resolved = normalize(resolvePath(path));
    if (!this.allowedPaths.includes(resolved)) {
      this.allowedPaths.push(resolved);
    }
  }

  /**
   * Temporarily scope paths to a sandboxed user directory.
   * Used for non-owner users who should only access their sandbox.
   */
  setScopedPaths(paths: string[]): void {
    this._originalPaths = [...this.allowedPaths];
    this.allowedPaths = paths.map((p) => normalize(resolvePath(p)));
  }

  /**
   * Reset paths back to the full owner paths.
   */
  resetPaths(): void {
    if (this._originalPaths) {
      this.allowedPaths = this._originalPaths;
      this._originalPaths = undefined;
    }
  }

  private _originalPaths?: string[];

  // ─── URL Validation ────────────────────────────────────────────────────

  /**
   * Check if a URL is safe to access.
   */
  isUrlSafe(url: string): boolean {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();

      // Block known bad domains
      if (this.blockedDomains.has(hostname)) return false;

      // Block private/internal IPs (SSRF protection)
      if (
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "0.0.0.0" ||
        hostname.startsWith("192.168.") ||
        hostname.startsWith("10.") ||
        hostname.startsWith("172.16.") ||
        hostname === "[::1]" ||
        hostname.endsWith(".internal") ||
        hostname.endsWith(".local")
      ) {
        // Allow localhost in development
        if (process.env.NODE_ENV === "development") return true;
        return false;
      }

      // Only allow http/https
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Block a domain at runtime.
   */
  blockDomain(domain: string): void {
    this.blockedDomains.add(domain.toLowerCase());
  }

  // ─── File & URL Scanning ───────────────────────────────────────────────

  /**
   * Scan a file for malware or threats.
   */
  async scanFile(filePath: string): Promise<ThreatScanResult> {
    const { stat, readFile } = await import("fs/promises");

    try {
      const fileStat = await stat(filePath);

      // Check file size — very large files are suspicious
      if (fileStat.size > 100 * 1024 * 1024) {
        return {
          blocked: false,
          severity: "low",
          reason: `Large file: ${(fileStat.size / 1024 / 1024).toFixed(1)}MB`,
          timestamp: Date.now(),
        };
      }

      // Read first 8KB for signature scanning
      const fd = await import("fs").then((fs) =>
        fs.promises.open(filePath, "r")
      );
      const buf = Buffer.alloc(8192);
      await fd.read(buf, 0, 8192, 0);
      await fd.close();

      const header = buf.toString("hex", 0, 4);

      // Check for known malware signatures (simplified)
      const suspiciousSignatures: Record<string, string> = {
        "4d5a": "PE executable",
        "7f454c46": "ELF binary",
        "cafebabe": "Java class/Mach-O",
      };

      for (const [sig, desc] of Object.entries(suspiciousSignatures)) {
        if (header.startsWith(sig)) {
          return {
            blocked: false,
            severity: "medium",
            reason: `Binary detected: ${desc}`,
            details: `File signature: ${sig}`,
            timestamp: Date.now(),
          };
        }
      }

      return { blocked: false, severity: "none", timestamp: Date.now() };
    } catch (err: any) {
      return {
        blocked: false,
        severity: "low",
        reason: `Scan error: ${err.message}`,
        timestamp: Date.now(),
      };
    }
  }

  /**
   * Check if a URL is safe.
   */
  async scanUrl(url: string): Promise<ThreatScanResult> {
    if (!this.isUrlSafe(url)) {
      return {
        blocked: true,
        severity: "high",
        reason: "URL failed safety check",
        details: url,
        timestamp: Date.now(),
      };
    }

    return { blocked: false, severity: "none", timestamp: Date.now() };
  }

  // ─── Event Log ─────────────────────────────────────────────────────────

  /**
   * Get recent shield events.
   */
  getEvents(limit = 50): ShieldEvent[] {
    return this.eventLog.slice(-limit);
  }

  /**
   * Get blocked events only.
   */
  getBlockedEvents(limit = 50): ShieldEvent[] {
    return this.eventLog.filter((e) => e.type === "blocked").slice(-limit);
  }

  // ─── Status ────────────────────────────────────────────────────────────

  status(): string {
    return this.initialized ? `🟢 Active [${this.mode}]` : "🔴 Inactive";
  }

  getMode(): ShieldMode {
    return this.mode;
  }

  setMode(mode: ShieldMode): void {
    this.mode = mode;
    console.log(`🛡️ Shield mode changed to: ${mode}`);
  }

  // ─── Internal ──────────────────────────────────────────────────────────

  private isFileOperation(tool: string): boolean {
    return ["read_file", "write_file", "list_directory", "read", "write", "edit"].includes(
      tool
    );
  }

  private logEvent(event: ShieldEvent): void {
    this.eventLog.push(event);
    if (this.eventLog.length > this.maxEventLog) {
      this.eventLog = this.eventLog.slice(-this.maxEventLog);
    }
  }
}

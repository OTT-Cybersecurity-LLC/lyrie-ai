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
 * - Protect device and file system
 * - WAF capabilities for web-facing endpoints
 */

export interface ThreatScanResult {
  blocked: boolean;
  reason?: string;
  severity: "none" | "low" | "medium" | "high" | "critical";
  details?: string;
}

export interface ToolCallValidation {
  tool: string;
  args: any;
  risk: "safe" | "moderate" | "dangerous";
}

export class ShieldManager {
  private initialized = false;
  private blockedPatterns: RegExp[] = [];
  private allowedPaths: string[] = [];
  private allowedCommands: string[] = [];

  async initialize(): Promise<void> {
    // Load security rules
    this.blockedPatterns = [
      // Prompt injection patterns
      /ignore.*previous.*instructions/i,
      /you are now/i,
      /system.*prompt.*override/i,
      /forget.*everything/i,
      
      // Dangerous command patterns
      /rm\s+-rf\s+\//,
      /format\s+[a-z]:/i,
      /dd\s+if=.*of=\/dev/,
      /:\(\)\{.*\|.*&\s*\}/,  // Fork bomb
      
      // Credential exfiltration
      /curl.*webhook.*password/i,
      /base64.*api.key/i,
    ];

    // Default allowed workspace paths
    this.allowedPaths = [
      process.cwd(),
      `${process.env.HOME}/.lyrie/`,
    ];

    this.initialized = true;
    console.log("   → Shield active: input scanning, tool validation, path scoping");
  }

  /**
   * Scan user input for potential threats.
   */
  async scanInput(input: string): Promise<ThreatScanResult> {
    if (!this.initialized) {
      return { blocked: false, severity: "none" };
    }

    for (const pattern of this.blockedPatterns) {
      if (pattern.test(input)) {
        return {
          blocked: true,
          reason: `Blocked: potential security threat detected`,
          severity: "high",
          details: `Pattern match: ${pattern.source}`,
        };
      }
    }

    return { blocked: false, severity: "none" };
  }

  /**
   * Validate a tool call before execution.
   * This is the security gate — nothing executes without Shield approval.
   */
  async validateToolCall(call: ToolCallValidation): Promise<boolean> {
    const { tool, args, risk } = call;

    // Always block dangerous operations without explicit approval
    if (risk === "dangerous") {
      console.warn(`🛡️ Shield BLOCKED dangerous tool call: ${tool}`);
      return false;
    }

    // Validate file paths are within allowed workspace
    if (tool === "read" || tool === "write" || tool === "edit") {
      const path = args.path || "";
      const isAllowed = this.allowedPaths.some((allowed) => path.startsWith(allowed));
      if (!isAllowed) {
        console.warn(`🛡️ Shield BLOCKED file access outside workspace: ${path}`);
        return false;
      }
    }

    // Validate shell commands
    if (tool === "exec") {
      const command = args.command || "";
      // Check for dangerous patterns
      for (const pattern of this.blockedPatterns) {
        if (pattern.test(command)) {
          console.warn(`🛡️ Shield BLOCKED dangerous command: ${command.substring(0, 50)}...`);
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Scan a file for malware or threats.
   */
  async scanFile(filePath: string): Promise<ThreatScanResult> {
    // TODO: Integrate with Rust shield binary for deep scanning
    return { blocked: false, severity: "none" };
  }

  /**
   * Check if a URL is safe.
   */
  async scanUrl(url: string): Promise<ThreatScanResult> {
    // TODO: Check against threat intelligence databases
    return { blocked: false, severity: "none" };
  }

  status(): string {
    return this.initialized ? "🟢 Active" : "🔴 Inactive";
  }
}

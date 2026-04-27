/**
 * SkillManager — Self-improving skill system for Lyrie Agent.
 *
 * Skills are persistent, tracked, and improve over time.
 * Stored as JSON in ~/.lyrie/skills/ for portability and sharing.
 *
 * Features:
 * - Built-in skills: web-search, code-writer, file-manager, threat-scanner, system-monitor
 * - Persistent storage as JSON files
 * - Usage tracking with success/failure rates
 * - Pattern extraction from successful complex tasks
 * - Export/import for skill sharing
 *
 * © OTT Cybersecurity LLC — Production quality.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from "fs";
import { join, basename } from "path";

import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SkillStep {
  action: string;
  description: string;
  params?: Record<string, any>;
}

export interface SkillDefinition {
  id: string;
  name: string;
  description: string;
  version: number;
  triggerPatterns: string[];
  executionSteps: SkillStep[];
  tags: string[];
  builtIn: boolean;
  // Tracking
  successRate: number;
  timesUsed: number;
  timesSucceeded: number;
  timesFailed: number;
  lastUsed?: string;
  lastImproved?: string;
  createdAt: string;
  updatedAt: string;
}

export interface SkillExecutionResult {
  success: boolean;
  output: any;
  duration: number;
  error?: string;
}

export interface SkillExtractionCandidate {
  name: string;
  description: string;
  triggerPatterns: string[];
  executionSteps: SkillStep[];
  confidence: number;
}

// ─── Built-in Skill Definitions ──────────────────────────────────────────────

function createBuiltIn(
  id: string,
  name: string,
  description: string,
  triggers: string[],
  steps: SkillStep[],
  tags: string[] = []
): SkillDefinition {
  const now = new Date().toISOString();
  return {
    id,
    name,
    description,
    version: 1,
    triggerPatterns: triggers,
    executionSteps: steps,
    tags: ["built-in", ...tags],
    builtIn: true,
    successRate: 1.0,
    timesUsed: 0,
    timesSucceeded: 0,
    timesFailed: 0,
    createdAt: now,
    updatedAt: now,
  };
}

const BUILT_IN_SKILLS: SkillDefinition[] = [
  createBuiltIn(
    "web-search",
    "Web Search",
    "Search the web and return structured results. Supports multiple search engines and result filtering.",
    ["search", "find", "look up", "what is", "who is", "google", "search for"],
    [
      { action: "parse_query", description: "Extract search terms from user input" },
      { action: "execute_search", description: "Run search against configured engine", params: { engines: ["brave", "exa", "tavily"] } },
      { action: "rank_results", description: "Score and rank results by relevance" },
      { action: "format_output", description: "Return top results with titles, URLs, snippets" },
    ],
    ["search", "web", "research"]
  ),

  createBuiltIn(
    "code-writer",
    "Code Writer",
    "Generate code based on natural language description. Supports multiple languages and frameworks.",
    ["write code", "generate code", "create a function", "implement", "code for", "script that", "program to"],
    [
      { action: "analyze_request", description: "Determine language, framework, and requirements" },
      { action: "generate_code", description: "Write the code using LLM" },
      { action: "validate_syntax", description: "Check syntax and basic correctness" },
      { action: "add_tests", description: "Generate basic test cases if appropriate" },
      { action: "format_output", description: "Return formatted code with explanation" },
    ],
    ["code", "programming", "development"]
  ),

  createBuiltIn(
    "file-manager",
    "File Manager",
    "Read, write, list, and organize files on disk. Supports search, move, copy, and bulk operations.",
    ["read file", "write file", "list files", "find file", "create file", "delete file", "move file", "organize"],
    [
      { action: "parse_intent", description: "Determine file operation type" },
      { action: "resolve_path", description: "Resolve and validate file path" },
      { action: "execute_operation", description: "Perform the file operation" },
      { action: "verify_result", description: "Confirm operation succeeded" },
    ],
    ["files", "filesystem", "storage"]
  ),

  createBuiltIn(
    "threat-scanner",
    "Threat Scanner",
    "Scan URLs, files, and IPs for security threats. Integrates with Lyrie Shield for deep analysis.",
    ["scan", "threat", "malware", "virus", "security check", "is this safe", "check url", "analyze threat"],
    [
      { action: "classify_target", description: "Determine if scanning URL, file, IP, or domain" },
      { action: "quick_scan", description: "Run lightweight signature-based check" },
      { action: "deep_scan", description: "Run behavioral analysis via Shield engine", params: { timeout: 30000 } },
      { action: "check_reputation", description: "Query threat intelligence databases" },
      { action: "report", description: "Return threat assessment with severity and recommendations" },
    ],
    ["security", "cybersecurity", "scanning", "threats"]
  ),

  createBuiltIn(
    "system-monitor",
    "System Monitor",
    "Check system health: CPU, memory, disk, processes, network. Detect anomalies and report issues.",
    ["system health", "check system", "disk space", "memory usage", "cpu", "processes", "system status", "monitor"],
    [
      { action: "collect_metrics", description: "Gather CPU, RAM, disk, and network stats" },
      { action: "check_processes", description: "List top processes by resource usage" },
      { action: "detect_anomalies", description: "Flag unusual resource consumption" },
      { action: "format_report", description: "Return formatted system health report" },
    ],
    ["system", "monitoring", "devops", "health"]
  ),
];

// ─── SkillManager ────────────────────────────────────────────────────────────

export class SkillManager {
  private skills: Map<string, SkillDefinition> = new Map();
  private skillsDir: string;
  private executors: Map<string, (context: any) => Promise<SkillExecutionResult>> = new Map();
  private initialized = false;

  constructor(skillsDir?: string) {
    this.skillsDir = skillsDir || join(process.env.HOME || "~", ".lyrie", "skills");
  }

  async initialize(): Promise<void> {
    // Ensure skills directory
    if (!existsSync(this.skillsDir)) {
      mkdirSync(this.skillsDir, { recursive: true });
    }

    // Load built-in skills
    this.loadBuiltInSkills();

    // Load user skills from disk
    this.loadUserSkills();

    this.initialized = true;
    const builtIn = Array.from(this.skills.values()).filter((s) => s.builtIn).length;
    const user = this.skills.size - builtIn;
    console.log(`   → Skills loaded: ${builtIn} built-in, ${user} user-created`);
  }

  // ─── Built-in Skills ─────────────────────────────────────────────────────

  private loadBuiltInSkills(): void {
    for (const skill of BUILT_IN_SKILLS) {
      this.skills.set(skill.id, skill);
      // Save to disk if not already there (first run)
      const path = join(this.skillsDir, `${skill.id}.json`);
      if (!existsSync(path)) {
        this.saveToDisk(skill);
      } else {
        // Load the on-disk version to preserve usage stats
        try {
          const onDisk = JSON.parse(readFileSync(path, "utf-8")) as SkillDefinition;
          // Merge: keep built-in definition but preserve stats
          this.skills.set(skill.id, {
            ...skill,
            timesUsed: onDisk.timesUsed || 0,
            timesSucceeded: onDisk.timesSucceeded || 0,
            timesFailed: onDisk.timesFailed || 0,
            successRate: onDisk.successRate ?? 1.0,
            lastUsed: onDisk.lastUsed,
            lastImproved: onDisk.lastImproved,
          });
        } catch {}
      }
    }
  }

  // ─── User Skills ─────────────────────────────────────────────────────────

  private loadUserSkills(): void {
    if (!existsSync(this.skillsDir)) return;

    const files = readdirSync(this.skillsDir).filter((f) => f.endsWith(".json"));
    for (const file of files) {
      const id = basename(file, ".json");
      if (this.skills.has(id)) continue; // Already loaded as built-in

      try {
        const data = JSON.parse(readFileSync(join(this.skillsDir, file), "utf-8")) as SkillDefinition;
        if (data.id && data.name) {
          this.skills.set(data.id, data);
        }
      } catch (err) {
        console.warn(`⚠️ Failed to load skill: ${file}`, err);
      }
    }
  }

  // ─── Persistence ─────────────────────────────────────────────────────────

  private saveToDisk(skill: SkillDefinition): void {
    const path = join(this.skillsDir, `${skill.id}.json`);
    writeFileSync(path, JSON.stringify(skill, null, 2), "utf-8");
  }

  // ─── CRUD ────────────────────────────────────────────────────────────────

  register(skill: SkillDefinition): void {
    skill.updatedAt = new Date().toISOString();
    this.skills.set(skill.id, skill);
    this.saveToDisk(skill);
  }

  unregister(id: string): boolean {
    const skill = this.skills.get(id);
    if (!skill || skill.builtIn) return false; // Can't remove built-ins
    this.skills.delete(id);
    const path = join(this.skillsDir, `${id}.json`);
    if (existsSync(path)) unlinkSync(path);
    return true;
  }

  get(id: string): SkillDefinition | undefined {
    return this.skills.get(id);
  }

  getAll(): SkillDefinition[] {
    return Array.from(this.skills.values());
  }

  getBuiltIn(): SkillDefinition[] {
    return this.getAll().filter((s) => s.builtIn);
  }

  getUserSkills(): SkillDefinition[] {
    return this.getAll().filter((s) => !s.builtIn);
  }

  // ─── Skill Matching ──────────────────────────────────────────────────────

  /**
   * Find the best matching skill for a given input.
   * Returns the skill with the highest match confidence.
   */
  findSkill(input: string): { skill: SkillDefinition; confidence: number } | null {
    const inputLower = input.toLowerCase();
    let bestMatch: { skill: SkillDefinition; confidence: number } | null = null;

    for (const skill of this.skills.values()) {
      let confidence = 0;

      for (const pattern of skill.triggerPatterns) {
        const patternLower = pattern.toLowerCase();

        // Exact phrase match
        if (inputLower.includes(patternLower)) {
          const patternWeight = patternLower.split(/\s+/).length; // Multi-word patterns score higher
          confidence = Math.max(confidence, 0.5 + patternWeight * 0.15);
        }

        // Word-level match (all words in pattern found in input)
        const patternWords = patternLower.split(/\s+/);
        const matchedWords = patternWords.filter((w) => inputLower.includes(w));
        if (matchedWords.length === patternWords.length) {
          confidence = Math.max(confidence, 0.4 + matchedWords.length * 0.1);
        }
      }

      // Tag match bonus
      for (const tag of skill.tags) {
        if (inputLower.includes(tag.toLowerCase())) {
          confidence += 0.05;
        }
      }

      // Boost skills with higher success rates
      confidence *= 0.8 + skill.successRate * 0.2;

      if (confidence > 0.3 && (!bestMatch || confidence > bestMatch.confidence)) {
        bestMatch = { skill, confidence: Math.min(confidence, 1.0) };
      }
    }

    return bestMatch;
  }

  /**
   * Find all skills that could match an input, ranked by confidence.
   */
  findAllMatching(input: string, minConfidence: number = 0.2): Array<{ skill: SkillDefinition; confidence: number }> {
    const inputLower = input.toLowerCase();
    const matches: Array<{ skill: SkillDefinition; confidence: number }> = [];

    for (const skill of this.skills.values()) {
      let confidence = 0;
      for (const pattern of skill.triggerPatterns) {
        if (inputLower.includes(pattern.toLowerCase())) {
          confidence = Math.max(confidence, 0.5 + pattern.split(/\s+/).length * 0.1);
        }
      }
      if (confidence >= minConfidence) {
        matches.push({ skill, confidence });
      }
    }

    return matches.sort((a, b) => b.confidence - a.confidence);
  }

  // ─── Execution Tracking ──────────────────────────────────────────────────

  /**
   * Register a runtime executor for a skill.
   */
  registerExecutor(skillId: string, executor: (context: any) => Promise<SkillExecutionResult>): void {
    this.executors.set(skillId, executor);
  }

  /** Shield guard used to scan skill outputs before they reach the agent. */
  private outputShield: ShieldGuardLike = ShieldGuard.fallback();

  /** Override the default Shield guard (e.g. inject a real ShieldManager). */
  setOutputShield(guard: ShieldGuardLike): void {
    this.outputShield = guard;
  }

  /**
   * Execute a skill and track the result.
   *
   * Shield Doctrine: every skill output is scanned through the Shield guard.
   * Skills frequently shell out, scrape pages, or call third-party APIs —
   * exactly the surfaces where prompt-injection / credential exfil shows up.
   * Unsafe output is redacted with a clear Shield notice; the structural
   * recall is preserved so the agent still knows the skill ran.
   */
  async execute(skillId: string, context: any): Promise<SkillExecutionResult> {
    const skill = this.skills.get(skillId);
    if (!skill) {
      return { success: false, output: null, duration: 0, error: `Skill not found: ${skillId}` };
    }

    const executor = this.executors.get(skillId);
    if (!executor) {
      return { success: false, output: null, duration: 0, error: `No executor registered for: ${skillId}` };
    }

    const start = Date.now();
    try {
      const result = await executor(context);
      const duration = Date.now() - start;
      const filtered = result.success ? this.shieldFilter(skillId, result) : result;

      // Track usage
      skill.timesUsed++;
      if (filtered.success) {
        skill.timesSucceeded++;
      } else {
        skill.timesFailed++;
      }
      skill.successRate = skill.timesUsed > 0 ? skill.timesSucceeded / skill.timesUsed : 1.0;
      skill.lastUsed = new Date().toISOString();
      skill.updatedAt = new Date().toISOString();

      this.saveToDisk(skill);
      return { ...filtered, duration };
    } catch (err: any) {
      const duration = Date.now() - start;
      skill.timesUsed++;
      skill.timesFailed++;
      skill.successRate = skill.timesSucceeded / skill.timesUsed;
      skill.lastUsed = new Date().toISOString();
      this.saveToDisk(skill);
      return { success: false, output: null, duration, error: err.message || String(err) };
    }
  }

  /** Redact skill output that fails the Shield's recalled-text check. */
  private shieldFilter(skillId: string, result: SkillExecutionResult): SkillExecutionResult {
    const text = typeof result.output === "string"
      ? result.output
      : (result.output != null ? JSON.stringify(result.output) : "");
    if (!text) return result;
    const verdict = this.outputShield.scanRecalled(text);
    if (!verdict.blocked) return result;
    return {
      success: result.success,
      output: `⚠️ Lyrie Shield redacted skill \"${skillId}\" output: ${verdict.reason ?? "unsafe content"}`,
      duration: result.duration,
      error: result.error,
    };
  }

  // ─── Self-Improvement ────────────────────────────────────────────────────

  /**
   * After a complex task is completed, analyze whether a reusable skill can be extracted.
   *
   * Criteria:
   * 1. The task took multiple steps
   * 2. It was completed successfully
   * 3. A similar pattern has appeared before (or the pattern is generalizable)
   * 4. The pattern doesn't already exist as a skill
   */
  async checkForImprovement(
    input: string,
    output: any,
    steps: SkillStep[],
    success: boolean
  ): Promise<SkillExtractionCandidate | null> {
    if (!success || steps.length < 2) return null;

    // Check if this pattern already matches an existing skill well
    const existingMatch = this.findSkill(input);
    if (existingMatch && existingMatch.confidence > 0.7) return null;

    // Extract potential trigger patterns from the input
    const words = input.toLowerCase().split(/\s+/).filter((w) => w.length > 3);
    // Find the most distinctive 2-3 word combinations
    const triggerPatterns: string[] = [];
    if (words.length >= 2) {
      // Bigrams
      for (let i = 0; i < words.length - 1; i++) {
        triggerPatterns.push(`${words[i]} ${words[i + 1]}`);
      }
    }
    if (triggerPatterns.length === 0 && words.length > 0) {
      triggerPatterns.push(words[0]);
    }

    // Only suggest if we have reasonable triggers
    if (triggerPatterns.length === 0) return null;

    const candidate: SkillExtractionCandidate = {
      name: `Learned: ${input.slice(0, 50)}`,
      description: `Auto-extracted skill from successful task: "${input.slice(0, 100)}"`,
      triggerPatterns: triggerPatterns.slice(0, 5),
      executionSteps: steps,
      confidence: Math.min(0.3 + steps.length * 0.1, 0.9),
    };

    return candidate;
  }

  /**
   * Create a skill from an extraction candidate.
   */
  createFromCandidate(candidate: SkillExtractionCandidate): SkillDefinition {
    const id = `learned_${Date.now().toString(36)}`;
    const now = new Date().toISOString();
    const skill: SkillDefinition = {
      id,
      name: candidate.name,
      description: candidate.description,
      version: 1,
      triggerPatterns: candidate.triggerPatterns,
      executionSteps: candidate.executionSteps,
      tags: ["learned", "auto-extracted"],
      builtIn: false,
      successRate: 1.0,
      timesUsed: 0,
      timesSucceeded: 0,
      timesFailed: 0,
      createdAt: now,
      updatedAt: now,
    };

    this.register(skill);
    console.log(`🧠 New skill learned: "${skill.name}" (${skill.triggerPatterns.length} triggers)`);
    return skill;
  }

  // ─── Import / Export ─────────────────────────────────────────────────────

  /**
   * Export a skill to a shareable JSON string.
   */
  exportSkill(id: string): string | null {
    const skill = this.skills.get(id);
    if (!skill) return null;

    // Strip usage stats for clean export
    const exported = {
      ...skill,
      timesUsed: 0,
      timesSucceeded: 0,
      timesFailed: 0,
      successRate: 1.0,
      lastUsed: undefined,
    };
    return JSON.stringify(exported, null, 2);
  }

  /**
   * Import a skill from JSON string or object.
   */
  importSkill(data: string | SkillDefinition): SkillDefinition {
    const skill: SkillDefinition = typeof data === "string" ? JSON.parse(data) : { ...data };

    // Ensure required fields
    if (!skill.id || !skill.name) {
      throw new Error("Invalid skill: missing id or name");
    }

    // Reset stats on import
    skill.timesUsed = 0;
    skill.timesSucceeded = 0;
    skill.timesFailed = 0;
    skill.successRate = 1.0;
    skill.builtIn = false;
    skill.updatedAt = new Date().toISOString();

    this.register(skill);
    return skill;
  }

  /**
   * Export all user skills as a bundle.
   */
  exportAll(): string {
    const userSkills = this.getUserSkills();
    return JSON.stringify(userSkills, null, 2);
  }

  /**
   * Import a bundle of skills.
   */
  importAll(data: string): number {
    const skills: SkillDefinition[] = JSON.parse(data);
    let imported = 0;
    for (const skill of skills) {
      try {
        this.importSkill(skill);
        imported++;
      } catch (err) {
        console.warn(`⚠️ Skipped import of skill ${skill.id}:`, err);
      }
    }
    return imported;
  }

  // ─── Stats ───────────────────────────────────────────────────────────────

  stats(): {
    total: number;
    builtIn: number;
    learned: number;
    totalExecutions: number;
    avgSuccessRate: number;
    topSkills: Array<{ id: string; name: string; timesUsed: number; successRate: number }>;
  } {
    const all = this.getAll();
    const totalExec = all.reduce((sum, s) => sum + s.timesUsed, 0);
    const usedSkills = all.filter((s) => s.timesUsed > 0);
    const avgRate = usedSkills.length > 0
      ? usedSkills.reduce((sum, s) => sum + s.successRate, 0) / usedSkills.length
      : 1.0;

    const topSkills = [...all]
      .sort((a, b) => b.timesUsed - a.timesUsed)
      .slice(0, 5)
      .map((s) => ({ id: s.id, name: s.name, timesUsed: s.timesUsed, successRate: s.successRate }));

    return {
      total: all.length,
      builtIn: all.filter((s) => s.builtIn).length,
      learned: all.filter((s) => !s.builtIn).length,
      totalExecutions: totalExec,
      avgSuccessRate: Math.round(avgRate * 100) / 100,
      topSkills,
    };
  }

  status(): string {
    const s = this.stats();
    return `🧠 Skills: ${s.total} (${s.builtIn} built-in, ${s.learned} learned) | Executions: ${s.totalExecutions} | Avg success: ${(s.avgSuccessRate * 100).toFixed(0)}%`;
  }
}

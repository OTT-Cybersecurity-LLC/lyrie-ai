/**
 * Lyrie Agent — The world's first autonomous AI agent with built-in cybersecurity.
 *
 * This is the main entry point. It initializes:
 * 1. The Shield (security layer)
 * 2. The Memory Core (self-healing, versioned)
 * 3. The Agent Engine (autonomous execution)
 * 4. The Gateway (channels: Telegram, WhatsApp, etc.)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Re-exports for cross-package consumption ────────────────────────────────

// Report command (lyrie report)
export { runReportCommand, printReportHint } from "./report/report-command";
export type { ReportCommandOptions } from "./report/report-command";

// Engine
export { LyrieEngine } from "./engine/lyrie-engine";
export type { LyrieEngineConfig, Message, ParsedToolCall, ProcessResult } from "./engine/lyrie-engine";

// Model Router
export { ModelRouter } from "./engine/model-router";
export type { ModelConfig, ModelInstance, TaskType, RouterConfig } from "./engine/model-router";

// Shield
export { ShieldManager } from "./engine/shield-manager";
export type { ThreatScanResult, ToolCallValidation } from "./engine/shield-manager";

// Shield Guard — lightweight cross-cutting Shield contract used by every
// Lyrie module that touches untrusted text (memory recall, MCP results,
// gateway pairing, etc.). Doctrine: every layer has a Shield hook.
export { ShieldGuard, FallbackShieldGuard } from "./engine/shield-guard";
export type { ShieldGuardLike, ShieldVerdict } from "./engine/shield-guard";

// Lyrie Pentest — attack-surface mapper (`/understand`)
export { buildAttackSurface, MAPPER_VERSION as ATTACK_SURFACE_MAPPER_VERSION } from "./pentest/attack-surface";

// Lyrie AAV — Autonomous Adversarial Validation (red-team engine)
export { LyrieRedTeam, scoreVerdict } from "./aav/red-team";
export type { RedTeamTarget, RedTeamOptions, RedTeamScanResult, ProbeResult, ProbeVerdict, RedTeamMode } from "./aav/red-team";

// Lyrie AAV — Blue Team Scorer
export { LyrieBlueTeam } from "./aav/blue-team";
export type { DefenseReport, DefenseGrade, CategoryScore, Remediation } from "./aav/blue-team";

// Lyrie AAV — Reporter (SARIF, Markdown, JSON)
export { AavReporter } from "./aav/reporter";

// Lyrie AAV — Attack Corpus
export {
  ATTACK_CORPUS,
  CORPUS_VERSION,
  getByCategory,
  getBySeverity,
  getById,
  getCategories,
  getPreset,
  ENTRA_VECTORS,
  ENTRA_CORPUS_VERSION,
  STATE_ACTOR_VECTORS,
  STATE_ACTOR_CORPUS_VERSION,
} from "./aav/corpus/index";
export type { AttackVector, OwaspLlmCategory, AttackSeverity, AttackPreset } from "./aav/corpus/index";

// Lyrie Governance — AI Governance Scorecard
export { AiGovernanceScorecard, GOVERNANCE_QUESTIONS } from "./governance/scorecard";
export type {
  GovernanceTarget,
  GovernanceReport,
  GovernanceAnswers,
  GovernanceGap,
  MaturityLevel,
  EuAiActRisk,
  CategoryScore as GovernanceCategoryScore,
} from "./governance/scorecard";

// Lyrie Governance — Agent Permission Analyzer
export { AgentPermissionAnalyzer, parseToolManifest } from "./governance/permissions";
export type {
  ToolManifest,
  ToolDefinitionEntry,
  PermissionReport,
  PermissionFinding,
} from "./governance/permissions";

// Lyrie Pentest — Stages A–F exploitation validator
export {
  validateFinding,
  validateBatch,
  VALIDATOR_VERSION as STAGES_VALIDATOR_VERSION,
} from "./pentest/stages-validator";

// Lyrie Execution Backends — local / Daytona / Modal pluggable runner backends
export {
  SUPPORTED_BACKENDS as LYRIE_SUPPORTED_BACKENDS,
  LocalBackend,
  DaytonaBackend,
  ModalBackend,
  emptySarif as lyrieEmptySarif,
  extractSarifSummary as lyrieExtractSarifSummary,
  describeBackend as lyrieDescribeBackend,
  getBackend as lyrieGetBackend,
  readDaytonaConfigFromEnv as lyrieReadDaytonaConfig,
  readLocalConfigFromEnv as lyrieReadLocalConfig,
  readModalConfigFromEnv as lyrieReadModalConfig,
  resolveBackendKind as lyrieResolveBackendKind,
} from "./backends";
export type {
  AnyBackendConfig,
  Backend,
  BackendFactoryOptions,
  BackendKind,
  BackendResourceHints,
  BackendRunRequest,
  BackendRunResult,
  DaytonaBackendConfig,
  FetchFn as LyrieBackendFetchFn,
  LocalBackendConfig,
  ModalBackendConfig,
} from "./backends";

// Lyrie Tools Catalog — vetted external-tool registry + recommend-by-intent
export {
  ToolsCatalog,
  CATEGORIES as LYRIE_TOOL_CATEGORIES,
  CATEGORY_BY_ID as LYRIE_TOOL_CATEGORY_BY_ID,
  BUILTIN_TOOLS as LYRIE_BUILTIN_TOOLS,
  BUILTIN_TOOL_COUNT as LYRIE_BUILTIN_TOOL_COUNT,
  CATALOG_VERSION as LYRIE_TOOLS_CATALOG_VERSION,
  CATALOG_SIGNATURE as LYRIE_TOOLS_CATALOG_SIGNATURE,
} from "./tools-catalog";
export type {
  ToolDefinition,
  ToolCategory,
  ToolTag,
  ToolInstall,
  InstallKind,
  InstallStatus,
  CatalogStats,
  CategoryDescriptor,
  SupportedOS,
} from "./tools-catalog";

// Lyrie Pentest — HTTP Proxy (request/response inspection + replay + mutators)
export {
  LyrieHttpProxy,
  PROXY_VERSION,
  classifySurface as lyrieClassifyHttpSurface,
  detectSignals as lyrieDetectHttpSignals,
  applyMutator as lyrieApplyHttpMutator,
} from "./pentest/proxy";
export type {
  HttpExchange,
  HttpMethod,
  HttpRequestRecord,
  HttpResponseRecord,
  HttpSignal,
  HttpSignalKind,
  HttpSurface,
  Mutator,
  MutatorKind,
  ProxyOptions,
  ReplayOptions,
  ReplayResult,
} from "./pentest/proxy";

// Lyrie Pentest — Threat-Intel client (research.lyrie.ai feed)
export {
  ThreatIntelClient,
  THREAT_INTEL_VERSION,
  DEFAULT_FEED_URL as LYRIE_THREAT_INTEL_FEED_URL,
  versionAffected as lyrieVersionAffected,
} from "./pentest/threat-intel";
export type {
  ThreatAdvisory,
  ThreatIntelMatch,
  ThreatIntelClientOptions,
  KevAttribution,
  AdvisorySeverity,
  AdvisorySource,
} from "./pentest/threat-intel";

// Lyrie Pentest — OSS-Scan service (research.lyrie.ai/scan)
export {
  runOssScan,
  validateRepoUrl,
  OSS_SCAN_VERSION,
  DEFAULT_ALLOWED_HOSTS as LYRIE_OSS_SCAN_ALLOWED_HOSTS,
} from "./pentest/oss-scan/service";
export type {
  OssScanRequest,
  OssScanResult,
  OssScanError,
  OssScanOptions,
} from "./pentest/oss-scan/service";

// Lyrie Pentest — multi-language vulnerability scanners
export {
  ALL_SCANNERS as LYRIE_LANGUAGE_SCANNERS,
  scanFiles as runLyrieMultilangScan,
  javascriptScanner,
  typescriptScanner,
  pythonScanner,
  goScanner,
  phpScanner,
  rubyScanner,
  cScanner,
  cppScanner,
} from "./pentest/scanners";
export type {
  Language,
  LanguageScanner,
  ScannerRule,
  ScanReport,
} from "./pentest/scanners";
export type {
  Stage,
  RawFinding,
  ValidatedFinding,
  StageVerdict,
  ValidatorOptions,
  VulnerabilityCategory,
  PoC,
  Remediation,
} from "./pentest/stages-validator";
export type {
  AttackSurface,
  EntryKind,
  EntryPoint,
  TrustBoundary,
  BoundaryKind,
  DataFlow,
  FlowSource,
  FlowSink,
  DependencyEntry,
  RiskHotspot,
  MapperOptions,
} from "./pentest/attack-surface";

// Lyrie EditEngine — diff-view edits with approval gates
export { EditEngine, buildUnifiedDiff } from "./edits/edit-engine";
export type {
  EditOperation,
  EditApprovalMode,
  EditRequest,
  EditPlan,
  EditApply,
  EditLedger,
  EditEngineOptions,
} from "./edits/edit-engine";

// Memory
export { MemoryCore } from "./memory/memory-core";
export type { MemoryEntry, Importance, Source } from "./memory/memory-core";

// Memory Integrity (ASI06 defense)
export { MemoryIntegrityChecker, InMemoryIntegrityStore } from "./memory/integrity-checker";
export type {
  HashedEntry,
  FailedEntry,
  IntegrityReport,
  VerificationResult,
  IntegrityStore,
  LlmProvider,
} from "./memory/integrity-checker";

// Daemon Engine (v1.0.0 proactive mode)
export { LyrieDaemon, DaemonEngine, LYRIE_TICK_PROMPT, DAEMON_TICK_PROMPT } from "./engine/daemon";
export type {
  DaemonConfig,
  TickEvent,
  TickResult,
  DaemonEngineConfig,
  DaemonTickResult,
  AdapterFinding,
} from "./engine/daemon";
export {
  ensureFtsIndex,
  searchAcrossSessions,
  summarizeSession,
  heuristicSummarizer,
} from "./memory/fts-search";
export type {
  CrossSessionHit,
  CrossSessionSearchOptions,
  SessionSummary,
  SessionSummarizer,
  SummarizeSessionOptions,
} from "./memory/fts-search";

// Tools
export { ToolExecutor } from "./tools/tool-executor";
export type { Tool, ToolCall, ToolResult, ToolParameter, AnthropicToolDef, OpenAIToolDef } from "./tools/tool-executor";

// Cron
export { CronManager } from "./cron/cron-manager";
export type { CronTask, CronInterval, CronExecution, CronManagerConfig } from "./cron/cron-manager";

// Sub-Agents
export { SubAgentManager } from "./agents/sub-agent";
export type { SubAgentTask, SubAgentResult, SubAgentConfig, SubAgentStatus } from "./agents/sub-agent";

// Skills
// SKILL.md runtime
export { SkillLoader } from "./skills/skill-loader";
export { SkillRegistry, buildSystemPromptBlock } from "./skills/skill-registry";
export { SkillRunner } from "./skills/skill-runner";
export { SkillSearch } from "./skills/skill-search";
export type { SkillManifest, SkillContext, ActivatedSkill } from "./skills/skill-types";

// Legacy JSON-skill manager
export { SkillManager } from "./skills/skill-manager";
export type { SkillDefinition, SkillStep, SkillExecutionResult } from "./skills/skill-manager";

// Config
export {
  getConfig,
  resetConfig,
  getConfiguredProviders,
  getConfiguredChannels,
  assertMinimalConfig,
} from "./config";
export type { LyrieConfig } from "./config";

// Providers
export {
  createProviderRegistry,
  AnthropicProvider,
  OpenAIProvider,
  GoogleProvider,
  XAIProvider,
  MiniMaxProvider,
  OllamaProvider,
} from "./engine/providers/index";
export type { Provider, ProviderRegistry } from "./engine/providers/index";

// Channel Gateway (from core)
export { ChannelGateway } from "./channels/gateway";
export type { ChannelConfig, ChannelGatewayConfig } from "./channels/gateway";

// Migration
export {
  detectInstalledPlatforms,
  runMigration,
  runAllMigrations,
  SUPPORTED_PLATFORMS,
} from "./migrate/index";
export type { MigrationResult, MigratorPlatform } from "./migrate/types";

// ─── Version ─────────────────────────────────────────────────────────────────

export const VERSION = "0.5.0";

// LyrieEvolve — Autonomous Self-Improvement
export { Scorer, SCORER_VERSION } from "./evolve/scorer";
export type { TaskOutcome, Domain, Score, DomainSignals, ScorerOptions } from "./evolve/scorer";
export type { CyberSignals, SeoSignals, TradingSignals, CodeSignals, GeneralSignals } from "./evolve/scorer";

export {
  SkillExtractor,
  HeuristicExtractorLLM,
  tokenize,
  cosineSimilarity,
  renderSkillMd,
  EXTRACTOR_VERSION,
} from "./evolve/skill-extractor";
export type { SkillPattern, ExtractionResult, ExtractorLLM, SkillExtractorOptions } from "./evolve/skill-extractor";

export { Contexture, mmrSelect, CONTEXTURE_VERSION, CONTEXTURE_TABLE } from "./evolve/contexture";
export type { SkillContext, RetrievalResult, ContextureOptions } from "./evolve/contexture";

export { runDreamCycle, findPruneCandidates, pruneSkills, DREAM_VERSION } from "./evolve/dream-cycle";
export type { DreamReport, DreamCycleOptions, PruneCandidate } from "./evolve/dream-cycle";

// ─── MCP Security Scanner ─────────────────────────────────────────────────────
export { MCPSecurityScanner } from "./security/mcp-scanner";
export type {
  MCPScanResult,
  MCPFinding,
  MCPRiskLevel,
  MCPFindingSeverity,
  MCPToolDecl,
  MCPServerConfig as MCPScannerServerConfig,
  MCPScannerOptions,
} from "./security/mcp-scanner";

// ─── Boot ────────────────────────────────────────────────────────────────────

import { LyrieEngine } from "./engine/lyrie-engine";
import { MemoryCore } from "./memory/memory-core";
import { ModelRouter } from "./engine/model-router";
import { ShieldManager } from "./engine/shield-manager";
import { ChannelGateway } from "./channels/gateway";
import { getConfig, assertMinimalConfig } from "./config";

async function main() {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║         🛡️  LYRIE AGENT v${VERSION}         ║
  ║   The AI that protects while it helps  ║
  ╚═══════════════════════════════════════╝
  `);

  // Load config and validate
  const config = getConfig();
  assertMinimalConfig(config);

  // Phase 1: Initialize the Shield (security first, always)
  console.log("🛡️  Initializing Shield...");
  const shield = new ShieldManager();
  await shield.initialize();

  // Phase 2: Initialize Memory (self-healing, versioned)
  console.log("🧠 Initializing Memory Core...");
  const memory = new MemoryCore();
  await memory.initialize();

  // Phase 3: Initialize Model Router with real API keys
  console.log("🔀 Initializing Model Router...");
  const router = new ModelRouter();
  await router.initialize({
    anthropicApiKey: config.anthropicApiKey,
    openaiApiKey: config.openaiApiKey,
    googleApiKey: config.googleApiKey,
    xaiApiKey: config.xaiApiKey,
    minimaxApiKey: config.minimaxApiKey,
    preferLocal: config.preferLocal,
  });

  // Phase 4: Initialize the Agent Engine
  console.log("⚡ Initializing Agent Engine...");
  const engine = new LyrieEngine({
    shield,
    memory,
    router,
    enableCron: true,
    maxToolTurns: 25,
    maxToolCalls: 50,
    subAgentConfig: { maxConcurrent: 5, defaultTimeout: 300000 },
  });
  await engine.initialize();

  // Phase 5: Start Channel Gateway
  console.log("📡 Starting Channel Gateway...");
  const gateway = new ChannelGateway({ engine });
  await gateway.start();

  const cronStatus = engine.getCron()?.stats();
  console.log(`
  ✅ Lyrie Agent is running.
  
  Channels: ${gateway.activeChannels().join(", ") || "CLI only"}
  Models:   ${router.availableModels().length} configured
  Tools:    ${engine.getTools().listNames().length} available (${engine.getTools().listNames().join(", ")})
  Cron:     ${cronStatus ? `${cronStatus.totalTasks} tasks scheduled` : "disabled"}
  Memory:   ${memory.status()}
  Shield:   ${shield.status()}
  
  Ready to protect and serve.
  `);
}

// Only run main() when executed directly, not when imported
const isDirectRun =
  typeof Bun !== "undefined"
    ? Bun.main === import.meta.path
    : process.argv[1]?.endsWith("core/src/index.ts");

if (isDirectRun) {
  // Check for sub-commands before starting the full agent
  const subCommand = process.argv[2];

  if (subCommand === "report") {
    // `lyrie report [--open] [--url] [--local] [<path.sarif>]`
    import("./report/report-command")
      .then(({ runReportCommand }) => {
        const args = process.argv.slice(3);
        const urlOnly = args.includes("--url");
        const local = args.includes("--local");
        const sarifPath = args.find((a) => !a.startsWith("--"));
        return runReportCommand({ urlOnly, local, sarifPath });
      })
      .then(() => process.exit(0))
      .catch((err: unknown) => {
        console.error("❌", err instanceof Error ? err.message : err);
        process.exit(1);
      });
  } else {
    main().catch((err) => {
      console.error("❌ Lyrie Agent failed to start:", err);
      process.exit(1);
    });
  }
}

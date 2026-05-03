/**
 * Lyrie Agent — Configuration Loader
 *
 * Loads environment variables, validates them, and exports a typed config.
 * Uses Zod for runtime validation. Fails fast on missing required keys.
 *
 * OTT Cybersecurity LLC
 */

import { z } from "zod";

// ─── Schema ─────────────────────────────────────────────────────────────────

const ConfigSchema = z.object({
  // AI Providers
  anthropicApiKey: z.string().optional(),
  openaiApiKey: z.string().optional(),
  googleApiKey: z.string().optional(),
  xaiApiKey: z.string().optional(),
  minimaxApiKey: z.string().optional(),
  minimaxGroupId: z.string().optional(),

  // Local Models
  ollamaBaseUrl: z.string().url().default("http://localhost:11434"),
  lmstudioBaseUrl: z.string().url().default("http://localhost:1234/v1"),
  hermesEndpoint: z.string().url().default("http://localhost:11434"),

  // ── Independence Layer (v1.0.0) ─────────────────────────────────────────
  /** Primary provider id ("hermes" | "ollama" | "lmstudio" | "anthropic" | …). */
  provider: z.string().default("hermes"),
  /** Primary model id (provider-specific). */
  model: z.string().optional(),
  /** Fallback provider if the primary fails. */
  fallbackProvider: z.string().default("ollama"),
  /** When true, refuse to call any non-local provider. Hard guard. */
  requireLocalProvider: z.boolean().default(false),
  /** When true, run main agent in coordinator (orchestrator-only) mode. */
  coordinatorMode: z.boolean().default(false),

  // Channel Tokens
  telegramBotToken: z.string().optional(),
  discordBotToken: z.string().optional(),
  slackBotToken: z.string().optional(),

  // Lyrie Behavior
  mode: z.enum(["cloud", "local", "hybrid"]).default("hybrid"),
  preferLocal: z.boolean().default(false),
  memoryPath: z.string().default(`${process.env.HOME ?? "/tmp"}/.lyrie/memory`),
  logLevel: z.enum(["debug", "info", "warn", "error"]).default("info"),
  shieldMode: z.enum(["passive", "active", "strict"]).default("active"),

  // Runtime
  nodeEnv: z.enum(["development", "production", "test"]).default("development"),
  version: z.string().default("0.1.0"),
});

export type LyrieConfig = z.infer<typeof ConfigSchema>;

// ─── Loader ──────────────────────────────────────────────────────────────────

function loadFromEnv(): LyrieConfig {
  const raw = {
    anthropicApiKey: process.env.ANTHROPIC_API_KEY,
    openaiApiKey: process.env.OPENAI_API_KEY,
    googleApiKey: process.env.GOOGLE_API_KEY,
    xaiApiKey: process.env.XAI_API_KEY,
    minimaxApiKey: process.env.MINIMAX_API_KEY,
    minimaxGroupId: process.env.MINIMAX_GROUP_ID,

    ollamaBaseUrl: process.env.OLLAMA_BASE_URL,
    lmstudioBaseUrl: process.env.LMSTUDIO_BASE_URL,
    hermesEndpoint: process.env.HERMES_ENDPOINT,

    provider: process.env.LYRIE_PROVIDER,
    model: process.env.LYRIE_MODEL,
    fallbackProvider: process.env.LYRIE_FALLBACK_PROVIDER,
    requireLocalProvider: process.env.LYRIE_REQUIRE_LOCAL === "true",
    coordinatorMode: process.env.LYRIE_COORDINATOR_MODE === "true",

    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN,
    discordBotToken: process.env.DISCORD_BOT_TOKEN,
    slackBotToken: process.env.SLACK_BOT_TOKEN,

    mode: process.env.LYRIE_MODE,
    preferLocal: process.env.LYRIE_PREFER_LOCAL === "true",
    memoryPath: process.env.LYRIE_MEMORY_PATH || undefined,
    logLevel: process.env.LYRIE_LOG_LEVEL,
    shieldMode: process.env.LYRIE_SHIELD_MODE,

    nodeEnv: process.env.NODE_ENV,
    version: process.env.npm_package_version ?? "0.1.0",
  };

  const result = ConfigSchema.safeParse(raw);

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Lyrie config validation failed:\n${issues}`);
  }

  return result.data;
}

// ─── Validation Helpers ──────────────────────────────────────────────────────

/**
 * Check which providers are configured and ready.
 */
export function getConfiguredProviders(config: LyrieConfig): string[] {
  const providers: string[] = [];

  if (config.anthropicApiKey) providers.push("anthropic");
  if (config.openaiApiKey) providers.push("openai");
  if (config.googleApiKey) providers.push("google");
  if (config.xaiApiKey) providers.push("xai");
  if (config.minimaxApiKey) providers.push("minimax");

  // Local is always available if Ollama is reachable (we just assume it is)
  if (config.preferLocal || config.mode === "local") {
    providers.push("ollama");
  }

  return providers;
}

/**
 * Get channels that are configured.
 */
export function getConfiguredChannels(config: LyrieConfig): string[] {
  const channels: string[] = ["cli"]; // CLI always available

  if (config.telegramBotToken) channels.push("telegram");
  if (config.discordBotToken) channels.push("discord");
  if (config.slackBotToken) channels.push("slack");

  return channels;
}

/**
 * Require at least one AI provider to be configured.
 * Called during agent startup — fails fast if nothing is usable.
 */
export function assertMinimalConfig(config: LyrieConfig): void {
  const providers = getConfiguredProviders(config);

  if (providers.length === 0) {
    throw new Error(
      "No AI providers configured. Set at least one API key in .env:\n" +
        "  ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, XAI_API_KEY, or MINIMAX_API_KEY\n" +
        "  Or set LYRIE_PREFER_LOCAL=true to use Ollama."
    );
  }
}

// ─── Singleton ───────────────────────────────────────────────────────────────

let _config: LyrieConfig | null = null;

/**
 * Get the global Lyrie config (singleton).
 * Loads once on first call, cached thereafter.
 */
export function getConfig(): LyrieConfig {
  if (!_config) {
    _config = loadFromEnv();
  }
  return _config;
}

/**
 * Reset config (for testing).
 */
export function resetConfig(): void {
  _config = null;
}

// ─── Export default ───────────────────────────────────────────────────────────

export default getConfig;

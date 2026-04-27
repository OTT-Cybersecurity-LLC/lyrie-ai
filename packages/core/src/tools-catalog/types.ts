/**
 * Lyrie Tools Catalog — shared types.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 *
 * The catalog gives Lyrie a structured, searchable, install-aware view
 * of every external security tool the agent can drive. Categories,
 * tags, install detectors, and recommend-by-intent — all Lyrie-native.
 *
 * Scope rule: Lyrie ONLY catalogs vetted defensive + validated-offensive
 * tools. Phishing kits, mass DDoS launchers, RATs, keyloggers, and
 * jamming gear are deliberately excluded — they don't belong in an
 * enterprise security platform's brand.
 */

export type ToolCategory =
  | "information-gathering"
  | "wordlist"
  | "sql-injection"
  | "web-attack"
  | "post-exploitation"
  | "forensics"
  | "exploit-framework"
  | "reverse-engineering"
  | "xss"
  | "active-directory"
  | "cloud-security"
  | "mobile-security"
  | "container-security"
  | "secrets"
  | "fuzzing"
  | "password-cracking"
  | "threat-intel"
  | "ssl-tls"
  | "supply-chain";

export type ToolTag =
  | "osint"
  | "scanner"
  | "web"
  | "api"
  | "cloud"
  | "mobile"
  | "ad"
  | "k8s"
  | "container"
  | "iac"
  | "ssl"
  | "secrets"
  | "fuzzer"
  | "static"
  | "dynamic"
  | "post-exploit"
  | "forensics"
  | "rev-eng"
  | "intel";

export type SupportedOS = "linux" | "macos" | "windows" | "any";

export type InstallKind = "go" | "pip" | "pipx" | "npm" | "cargo" | "brew" | "git" | "system" | "docker";

export interface ToolInstall {
  /** How the tool is installed (operator-readable). */
  kind: InstallKind;
  /** Install command shown to the operator. */
  command: string;
  /** Detector binary or module name to check for `installed` state. */
  detect: string;
  /** Optional version flag for `lyrie tools status`. */
  versionFlag?: string;
}

export interface ToolDefinition {
  /** Stable Lyrie id, kebab-case. */
  id: string;
  /** Human-friendly name. */
  name: string;
  /** Short description (one line, ≤140 chars). */
  description: string;
  /** Project homepage / repo. */
  homepage: string;
  /** SPDX-style license string. */
  license: string;
  category: ToolCategory;
  tags: ReadonlyArray<ToolTag>;
  install: ToolInstall;
  supportedOS: ReadonlyArray<SupportedOS>;
  /** True when Lyrie has a first-party adapter that wraps this tool. */
  hasAdapter?: boolean;
  /**
   * Free-text intents Lyrie's `recommend()` matches against. Keep them
   * natural — operators type things like "scan a network for open ports".
   */
  intents: ReadonlyArray<string>;
}

export interface InstallStatus {
  installed: boolean;
  version?: string;
  detectedPath?: string;
  reason?: string;
}

export interface CategoryDescriptor {
  id: ToolCategory;
  title: string;
  emoji: string;
  description: string;
}

export interface CatalogStats {
  total: number;
  byCategory: Record<ToolCategory, number>;
  byTag: Record<ToolTag, number>;
  installed: number;
  missing: number;
}

export const CATALOG_VERSION = "lyrie-tools-catalog-1.0.0";
export const CATALOG_SIGNATURE = "Lyrie.ai by OTT Cybersecurity LLC";

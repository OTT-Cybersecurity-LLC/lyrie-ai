/**
 * Lyrie Hack — Auto-Remediation suggestions.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Stage F++: takes a confirmed Stages A–F finding and emits a concrete
 * remediation suggestion — description, diff hint, optional test
 * command, CWE reference. Pure-static, no execution.
 *
 * Coverage:
 *   - SQL injection            → parameterized queries
 *   - XSS                      → output encoding / escaping
 *   - SSRF                     → URL allowlist / DNS pinning
 *   - Shell injection / RCE    → argv arrays / shlex.quote
 *   - Path traversal           → realpath + allow-root check
 *   - Deserialization          → safe loaders (json / yaml.safe_load)
 *   - Secret exposure          → env var + secret-manager redirection
 *   - Open redirect            → static allowlist
 *   - Prompt injection         → ShieldGuard wrapper
 *   - Auth bypass              → middleware audit
 *
 * © OTT Cybersecurity LLC.
 */

import type { ValidatedFinding, VulnerabilityCategory } from "../pentest/stages-validator";
import type { SecretFinding } from "./secret-detector";

export interface RemediationSuggestion {
  /** Plain-language description. */
  description: string;
  /** A short before/after diff sketch the operator can adapt. */
  diffHint?: { before: string; after: string };
  /** Suggested verification command. */
  testCommand?: string;
  /** CWE reference. */
  referenceCwe?: string;
  /** Reference URL (OWASP / CWE / vendor). */
  referenceUrl?: string;
  /** Confidence the suggestion fits the finding (0-1). */
  confidence: number;
  signature: "Lyrie.ai by OTT Cybersecurity LLC";
}

export const AUTO_REMEDIATION_VERSION = "lyrie-remediation-1.0.0";

/**
 * Map a validated Stages A–F finding to a remediation suggestion.
 * Returns `null` when the finding is not in our coverage matrix.
 */
export function suggestRemediation(v: ValidatedFinding): RemediationSuggestion | null {
  const f = v.finding;
  const category: VulnerabilityCategory = f.category ?? "other";
  switch (category) {
    case "sql-injection":
      return remediateSqlInjection(v);
    case "xss":
      return remediateXss(v);
    case "ssrf":
      return remediateSsrf(v);
    case "shell-injection":
    case "rce":
      return remediateShellInjection(v);
    case "path-traversal":
      return remediatePathTraversal(v);
    case "deserialization":
      return remediateDeserialization(v);
    case "secret-exposure":
      return remediateSecretExposure(v);
    case "open-redirect":
      return remediateOpenRedirect(v);
    case "prompt-injection":
      return remediatePromptInjection(v);
    case "auth-bypass":
      return remediateAuthBypass(v);
    case "csrf":
      return remediateCsrf(v);
    default:
      return null;
  }
}

/**
 * Map a SecretFinding → RemediationSuggestion (pre-validator path).
 */
export function suggestSecretRemediation(s: SecretFinding): RemediationSuggestion {
  const env = guessEnvName(s.type);
  return {
    description:
      `Remove the hardcoded ${humanType(s.type)} from \`${s.file}:${s.line}\` and ` +
      `inject it via an environment variable or a secret manager (Vault, ` +
      `AWS Secrets Manager, GCP Secret Manager). Rotate the credential immediately ` +
      `since exposure to git history must be assumed.`,
    diffHint: {
      before: `const apiKey = "${s.redactedSample}"`,
      after: `const apiKey = process.env.${env};\nif (!apiKey) throw new Error("${env} not configured");`,
    },
    testCommand: "git log --all --full-history -p -S '<redacted>' -- '*' # confirm rotation removed history hits",
    referenceCwe: "CWE-798",
    referenceUrl: "https://cwe.mitre.org/data/definitions/798.html",
    confidence: 0.95,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

// ─── per-class remediations ──────────────────────────────────────────────────

function remediateSqlInjection(v: ValidatedFinding): RemediationSuggestion {
  const evidence = v.finding.evidence ?? "";
  const isJs = /\b(query|execute)\s*\(\s*[`'"]/.test(evidence);
  const isPy = /\bcursor\.execute\s*\(/.test(evidence);
  let diffHint: RemediationSuggestion["diffHint"];
  if (isPy) {
    diffHint = {
      before: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
      after: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
    };
  } else if (isJs) {
    diffHint = {
      before: "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
      after: "db.query('SELECT * FROM users WHERE id = ?', [userId])",
    };
  } else {
    diffHint = {
      before: '"... WHERE id = " + userInput',
      after: 'parameterized("... WHERE id = ?", [userInput])',
    };
  }
  return {
    description:
      "Replace string concatenation / template interpolation in SQL with parameterized queries (bind variables). " +
      "Use the database driver's native placeholder syntax (`?`, `$1`, `:name`, `%s` depending on driver). " +
      "Never build SQL by concatenating untrusted input.",
    diffHint,
    testCommand:
      `bun test ${v.finding.file ?? ""} --pattern 'sql-injection'`,
    referenceCwe: v.finding.cwe ?? "CWE-89",
    referenceUrl: "https://owasp.org/www-community/attacks/SQL_Injection",
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateXss(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Encode untrusted input on the OUTPUT side, not on the input side. For HTML contexts use the framework's " +
      "auto-escaping (React, Vue, Svelte, Jinja2 with autoescape=True). For DOM sinks like `innerHTML`, prefer " +
      "`textContent` or use DOMPurify before injecting. For attributes, use the framework's binding (`:href`) " +
      "instead of string concatenation. Set CSP headers (`default-src 'self'; script-src 'self'`) as defense in depth.",
    diffHint: {
      before: "el.innerHTML = userInput",
      after:
        "el.textContent = userInput;\n// or, when HTML is required:\nimport DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(userInput);",
    },
    testCommand: "bun test --pattern 'xss'",
    referenceCwe: v.finding.cwe ?? "CWE-79",
    referenceUrl: "https://owasp.org/www-community/attacks/xss/",
    confidence: 0.85,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateSsrf(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Validate the destination URL against an explicit allowlist BEFORE issuing the request. " +
      "Reject private/loopback/link-local IPs (10.0.0.0/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fc00::/7). " +
      "Resolve DNS once, pin the resolved IP, and re-check it against the same blocklist. " +
      "Disable HTTP redirects or follow them with the same checks. Apply per-host rate limits.",
    diffHint: {
      before: "const res = await fetch(userUrl);",
      after:
        "import { isAllowedHost } from '@lyrie/core/security/url-guard';\n" +
        "if (!isAllowedHost(userUrl)) throw new Error('SSRF: host not on allowlist');\n" +
        "const res = await fetch(userUrl, { redirect: 'manual' });",
    },
    testCommand: "bun test --pattern 'ssrf'",
    referenceCwe: v.finding.cwe ?? "CWE-918",
    referenceUrl: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    confidence: 0.85,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateShellInjection(v: ValidatedFinding): RemediationSuggestion {
  const evidence = v.finding.evidence ?? "";
  const isPy = /subprocess|os\.system|os\.popen/.test(evidence);
  const isNode = /exec\(|execSync|spawn/.test(evidence) || (v.finding.file ?? "").match(/\.(?:js|ts|tsx|mjs)$/);
  let diffHint: RemediationSuggestion["diffHint"];
  if (isPy) {
    diffHint = {
      before: `subprocess.call(f"convert {filename} out.png", shell=True)`,
      after: `subprocess.run(["convert", filename, "out.png"], shell=False, check=True)`,
    };
  } else if (isNode) {
    diffHint = {
      before: "exec(`convert ${filename} out.png`)",
      after:
        "import { execFile } from 'node:child_process';\nexecFile('convert', [filename, 'out.png'], (err) => { /* … */ });",
    };
  } else {
    diffHint = {
      before: "system('convert ' + filename + ' out.png')",
      after:
        "// pass argv as an array, never as a single shell-parsed string",
    };
  }
  return {
    description:
      "Replace shell-string execution with argv-array invocations. Set `shell=False` (Python) / use " +
      "`execFile` instead of `exec` (Node). Validate filenames against a strict regex (`^[A-Za-z0-9._-]+$`) " +
      "and reject path separators where not intended.",
    diffHint,
    testCommand: "bun test --pattern 'shell-injection'",
    referenceCwe: v.finding.cwe ?? "CWE-78",
    referenceUrl: "https://owasp.org/www-community/attacks/Command_Injection",
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediatePathTraversal(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Resolve every user-supplied path with `realpath` (or `path.resolve`) and verify the result is " +
      "still inside the intended root directory. Reject paths containing `..`, NUL bytes, or absolute " +
      "prefixes after normalization. Prefer opaque ids over filenames in URLs.",
    diffHint: {
      before: "fs.readFile(path.join('/var/data', req.query.file))",
      after:
        "const root = path.resolve('/var/data');\n" +
        "const candidate = path.resolve(root, req.query.file);\n" +
        "if (!candidate.startsWith(root + path.sep)) throw new Error('path-traversal');\n" +
        "fs.readFile(candidate);",
    },
    testCommand: "bun test --pattern 'path-traversal'",
    referenceCwe: v.finding.cwe ?? "CWE-22",
    referenceUrl: "https://owasp.org/www-community/attacks/Path_Traversal",
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateDeserialization(v: ValidatedFinding): RemediationSuggestion {
  const evidence = v.finding.evidence ?? "";
  const isYaml = /yaml\.load|yaml\.unsafe_load|YAML\.load/i.test(evidence);
  const isPickle = /pickle\.loads|pickle\.load/.test(evidence);
  const isMarshal = /Marshal\.load/.test(evidence);
  let diffHint: RemediationSuggestion["diffHint"];
  if (isYaml) {
    diffHint = {
      before: "yaml.load(payload)",
      after: "yaml.safe_load(payload)  # never load() with untrusted input",
    };
  } else if (isPickle) {
    diffHint = {
      before: "pickle.loads(request.body)",
      after:
        "# Switch transport format. pickle is RCE-equivalent on untrusted input.\n" +
        "json.loads(request.body)  # or msgpack with a strict schema",
    };
  } else if (isMarshal) {
    diffHint = {
      before: "Marshal.load(params[:data])",
      after:
        "# Marshal.load is RCE-equivalent. Use JSON.parse with a schema check.\n" +
        "JSON.parse(params[:data])",
    };
  } else {
    diffHint = {
      before: "deserialize(untrustedBytes)",
      after: "// switch to a safe schema-driven format (JSON/Protobuf) and validate before use",
    };
  }
  return {
    description:
      "Replace insecure deserializers (pickle, Marshal, yaml.load, ObjectInputStream, BinaryFormatter) " +
      "with schema-driven safe formats (JSON + zod, Protobuf, MessagePack with a strict type registry). " +
      "If you must deserialize, sign the payload with HMAC and verify before parsing.",
    diffHint,
    testCommand: "bun test --pattern 'deserialization'",
    referenceCwe: v.finding.cwe ?? "CWE-502",
    referenceUrl: "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateSecretExposure(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Move the hardcoded credential into an environment variable or secret manager. Rotate the credential " +
      "immediately — git history exposure means it must be considered compromised. Add a pre-commit hook " +
      "running `lyrie secrets` on staged files to prevent recurrence.",
    diffHint: {
      before: 'const KEY = "AKIA…REDACTED"',
      after:
        "const KEY = process.env.AWS_ACCESS_KEY_ID;\nif (!KEY) throw new Error('AWS_ACCESS_KEY_ID not configured');",
    },
    testCommand: "bun run scripts/hack.ts --mode quick . # confirm 0 secret findings",
    referenceCwe: v.finding.cwe ?? "CWE-798",
    referenceUrl: "https://cwe.mitre.org/data/definitions/798.html",
    confidence: 0.95,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateOpenRedirect(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Replace user-supplied redirect destinations with an opaque id mapped to a static allowlist on the " +
      "server. If a free-form URL is required, validate the host against an explicit allowlist before issuing " +
      "the 3xx.",
    diffHint: {
      before: 'res.redirect(req.query.next)',
      after:
        "const ALLOWED = new Set(['/', '/dashboard', '/login']);\n" +
        "const next = String(req.query.next ?? '/');\n" +
        "res.redirect(ALLOWED.has(next) ? next : '/');",
    },
    testCommand: "bun test --pattern 'open-redirect'",
    referenceCwe: v.finding.cwe ?? "CWE-601",
    referenceUrl: "https://cwe.mitre.org/data/definitions/601.html",
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediatePromptInjection(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Wrap untrusted text passed into prompts with Lyrie's ShieldGuard.scanRecalled() before concatenation. " +
      "Treat retrieved content (RAG, MCP tool output, user uploads) as adversarial — never give it the same " +
      "trust level as system or developer messages.",
    diffHint: {
      before: 'const prompt = `${userQuery}\\n\\n${ragChunk}`',
      after:
        "import { ShieldGuard } from '@lyrie/core';\n" +
        "const guard = ShieldGuard.fallback();\n" +
        "const verdict = guard.scanRecalled(ragChunk);\n" +
        "if (verdict.blocked) ragChunk = '<redacted by Shield>';\n" +
        "const prompt = `${userQuery}\\n\\n${ragChunk}`;",
    },
    testCommand: "bun run scripts/redteam.ts --preset prompt-injection",
    referenceCwe: v.finding.cwe ?? "CWE-1427",
    referenceUrl: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    confidence: 0.85,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateAuthBypass(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Centralize authentication / authorization in middleware that applies BEFORE the handler executes, " +
      "and assert it is mounted on every protected route. Add a deny-by-default test that ensures unknown " +
      "routes return 401/403, not 200.",
    diffHint: {
      before: "// route handler with ad-hoc auth check inside",
      after:
        "app.use(authMiddleware);\napp.use(rbac({ require: 'admin' }));\napp.get('/admin', adminHandler);",
    },
    testCommand: "bun test --pattern 'auth'",
    referenceCwe: v.finding.cwe ?? "CWE-285",
    referenceUrl: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    confidence: 0.7,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function remediateCsrf(v: ValidatedFinding): RemediationSuggestion {
  return {
    description:
      "Require a CSRF token (synchronizer or double-submit cookie) on every state-changing request. " +
      "Set cookies as `SameSite=Strict; Secure; HttpOnly`. For APIs called from JavaScript, rely on the " +
      "`Origin`/`Referer` check + `SameSite=Strict` cookies and reject cross-origin POSTs.",
    diffHint: {
      before: "// no CSRF check on POST",
      after: "import csrf from 'csurf';\napp.use(csrf({ cookie: { sameSite: 'strict' } }));",
    },
    testCommand: "bun test --pattern 'csrf'",
    referenceCwe: v.finding.cwe ?? "CWE-352",
    referenceUrl: "https://owasp.org/www-community/attacks/csrf",
    confidence: 0.8,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

// ─── helpers ────────────────────────────────────────────────────────────────

function guessEnvName(t: SecretFinding["type"]): string {
  switch (t) {
    case "aws-access-key-id":
      return "AWS_ACCESS_KEY_ID";
    case "aws-secret-access-key":
      return "AWS_SECRET_ACCESS_KEY";
    case "github-pat":
    case "github-fine-grained-pat":
    case "github-app-token":
      return "GITHUB_TOKEN";
    case "stripe-live-key":
    case "stripe-restricted-key":
      return "STRIPE_API_KEY";
    case "openai-key":
      return "OPENAI_API_KEY";
    case "anthropic-key":
      return "ANTHROPIC_API_KEY";
    case "google-api-key":
      return "GOOGLE_API_KEY";
    case "slack-token":
      return "SLACK_BOT_TOKEN";
    default:
      return "SECRET_VALUE";
  }
}

function humanType(t: SecretFinding["type"]): string {
  return t.replace(/-/g, " ");
}

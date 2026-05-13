/**
 * Lyrie ML / Structural Shield File Classifier
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * A lightweight, zero-dependency structural threat classifier.  Extracts
 * entropy, byte-distribution, magic-byte, and API-pattern features from
 * raw file bytes, then runs a deterministic decision-tree to produce a
 * clean / suspicious / malicious verdict.
 *
 * When an AI endpoint is available, `classifyFileWithAI` sends the
 * extracted features + a printable head sample to the model for a
 * second-opinion classification and falls back to the rule-based tree
 * on any error.
 */

// ─── Public types ────────────────────────────────────────────────────────────

export interface FileFeatures {
  sizeBytes: number;
  entropy: number;
  entropyStdDev: number;
  printableRatio: number;
  nullByteRatio: number;
  highBitRatio: number;
  magicBytes: string;
  hasExecutableHeader: boolean;
  suspiciousStringCount: number;
  importCount: number;
  suspiciousApiPatterns: string[];
  obfuscationScore: number;
}

export interface ClassificationResult {
  verdict: "clean" | "suspicious" | "malicious";
  confidence: number;
  features: FileFeatures;
  reasons: string[];
  riskScore: number;
}

export interface AIClassifierConfig {
  endpoint: string;
  apiKey: string;
  model?: string;
  timeoutMs?: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const BLOCK_SIZE = 256;

const EXECUTABLE_MAGIC: ReadonlyArray<{ bytes: number[]; name: string }> = [
  { bytes: [0x7f, 0x45, 0x4c, 0x46],             name: "ELF" },
  { bytes: [0x4d, 0x5a],                          name: "PE/MZ" },
  { bytes: [0xfe, 0xed, 0xfa, 0xce],              name: "Mach-O 32" },
  { bytes: [0xfe, 0xed, 0xfa, 0xcf],              name: "Mach-O 64" },
  { bytes: [0xcf, 0xfa, 0xed, 0xfe],              name: "Mach-O 64 LE" },
  { bytes: [0xce, 0xfa, 0xed, 0xfe],              name: "Mach-O 32 LE" },
  { bytes: [0xca, 0xfe, 0xba, 0xbe],              name: "Mach-O Universal" },
];

const KNOWN_BINARY_MAGIC: ReadonlyArray<number[]> = [
  [0x89, 0x50, 0x4e, 0x47],       // PNG
  [0xff, 0xd8, 0xff],             // JPEG
  [0x47, 0x49, 0x46, 0x38],       // GIF
  [0x52, 0x49, 0x46, 0x46],       // RIFF (WebP, WAV, AVI)
  [0x25, 0x50, 0x44, 0x46],       // PDF
  [0x50, 0x4b, 0x03, 0x04],       // ZIP / DOCX / JAR
  [0x1f, 0x8b],                   // gzip
  [0x42, 0x5a, 0x68],             // bzip2
  [0xfd, 0x37, 0x7a, 0x58, 0x5a], // xz
];

const SUSPICIOUS_STRINGS: ReadonlyArray<RegExp> = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bsystem\s*\(/gi,
  /\bRuntime\.getRuntime\(\)/gi,
  /\bProcess(Builder)?\s*\(/gi,
  /\bShellExecute\b/gi,
  /\bWScript\.Shell\b/gi,
  /\bpowershell\b/gi,
  /\bcmd\.exe\b/gi,
  /\/bin\/sh\b/g,
  /\/bin\/bash\b/g,
  /\bCreateRemoteThread\b/gi,
  /\bVirtualAlloc(Ex)?\b/gi,
  /\bWriteProcessMemory\b/gi,
  /\bLoadLibrary[AW]?\b/gi,
  /\bGetProcAddress\b/gi,
  /\bNtCreateSection\b/gi,
  /\bbase64_decode\s*\(/gi,
  /\batob\s*\(/gi,
  /\bfromCharCode\b/gi,
  /\bunescape\s*\(/gi,
  /\bdocument\.write\s*\(/gi,
  /\bxmlhttp/gi,
  /\bActiveXObject\b/gi,
];

const SUSPICIOUS_API_CATEGORIES: ReadonlyArray<{
  label: string;
  patterns: ReadonlyArray<RegExp>;
}> = [
  {
    label: "network",
    patterns: [
      /\b(fetch|XMLHttpRequest|http\.request|net\.Socket|socket\.connect|urllib|requests\.get|curl_exec)\b/gi,
      /\b(WebSocket|ws:\/\/|wss:\/\/)\b/gi,
      /\bTCP|UDP|SOCK_STREAM\b/gi,
    ],
  },
  {
    label: "crypto",
    patterns: [
      /\b(createCipher|createDecipher|AES|RSA|encrypt|decrypt|CryptoJS)\b/gi,
      /\b(hashlib|hmac|bcrypt|scrypt)\b/gi,
    ],
  },
  {
    label: "process",
    patterns: [
      /\b(child_process|subprocess|os\.system|exec[A-Z]|spawn|fork|popen)\b/gi,
      /\b(Process|Runtime|CreateProcess|ShellExecute)\b/gi,
    ],
  },
  {
    label: "file",
    patterns: [
      /\b(readFile|writeFile|appendFile|unlink|rmdir|rename|chmod|chown)\b/gi,
      /\b(open|fopen|fwrite|fclose|fread|os\.remove|shutil)\b/gi,
      /\b(CreateFile|DeleteFile|MoveFile|CopyFile)\b/gi,
    ],
  },
  {
    label: "registry",
    patterns: [
      /\b(RegOpenKey|RegSetValue|RegDeleteKey|HKEY_LOCAL_MACHINE|HKLM|HKCU)\b/gi,
    ],
  },
  {
    label: "persistence",
    patterns: [
      /\b(crontab|systemd|launchd|schtasks|at\.exe|autostart|startup)\b/gi,
      /\bRunOnce|CurrentVersion\\Run\b/gi,
    ],
  },
];

const BINARY_FORMAT_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
  ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".avi", ".mkv", ".mov",
  ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".so", ".dylib", ".dll", ".a", ".lib",
  ".class", ".pyc", ".pyo",
]);

// ─── Feature extraction ─────────────────────────────────────────────────────

export function extractFeatures(content: Buffer, filename: string): FileFeatures {
  const size = content.length;
  if (size === 0) {
    return {
      sizeBytes: 0,
      entropy: 0,
      entropyStdDev: 0,
      printableRatio: 1,
      nullByteRatio: 0,
      highBitRatio: 0,
      magicBytes: "",
      hasExecutableHeader: false,
      suspiciousStringCount: 0,
      importCount: 0,
      suspiciousApiPatterns: [],
      obfuscationScore: 0,
    };
  }

  const magicBytes = content.subarray(0, 8)
    .reduce((acc, b) => acc + b.toString(16).padStart(2, "0"), "");

  const hasExecutableHeader = EXECUTABLE_MAGIC.some(
    (m) => m.bytes.every((b, i) => i < content.length && content[i] === b),
  );

  const freq = new Float64Array(256);
  let nullCount = 0;
  let highBitCount = 0;
  let printableCount = 0;

  for (let i = 0; i < size; i++) {
    const b = content[i];
    freq[b]++;
    if (b === 0x00) nullCount++;
    if (b > 0x7f) highBitCount++;
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) {
      printableCount++;
    }
  }

  const entropy = shannonEntropy(freq, size);
  const entropyStdDev = blockEntropyStdDev(content, BLOCK_SIZE);
  const printableRatio = printableCount / size;
  const nullByteRatio = nullCount / size;
  const highBitRatio = highBitCount / size;

  const text = content.toString("utf8", 0, Math.min(size, 65_536));

  let suspiciousStringCount = 0;
  for (const re of SUSPICIOUS_STRINGS) {
    re.lastIndex = 0;
    const matches = text.match(re);
    if (matches) suspiciousStringCount += matches.length;
  }

  const apiPatterns: string[] = [];
  let importCount = 0;
  for (const { label, patterns } of SUSPICIOUS_API_CATEGORIES) {
    let found = false;
    for (const re of patterns) {
      re.lastIndex = 0;
      const matches = text.match(re);
      if (matches) {
        importCount += matches.length;
        found = true;
      }
    }
    if (found) apiPatterns.push(label);
  }

  const obfuscationScore = computeObfuscationScore(text);

  return {
    sizeBytes: size,
    entropy,
    entropyStdDev,
    printableRatio,
    nullByteRatio,
    highBitRatio,
    magicBytes,
    hasExecutableHeader,
    suspiciousStringCount,
    importCount,
    suspiciousApiPatterns: apiPatterns,
    obfuscationScore,
  };
}

// ─── Rule-based classifier ──────────────────────────────────────────────────

export function classifyFile(content: Buffer, filename: string): ClassificationResult {
  const features = extractFeatures(content, filename);
  const reasons: string[] = [];
  let score = 0;

  // ── Decision tree ──────────────────────────────────────────────────────

  // Rule 1: High entropy + executable header → packed/encrypted binary
  if (features.entropy > 7.0 && features.hasExecutableHeader) {
    score += 40;
    reasons.push("High entropy (>7.0) with executable header — likely packed or encrypted binary");
  }

  // Rule 2: High entropy + many suspicious strings → obfuscated payload
  if (features.entropy > 6.5 && features.suspiciousStringCount > 5) {
    score += 30;
    reasons.push("Elevated entropy (>6.5) with >5 suspicious API strings — possible obfuscated payload");
  }

  // Rule 3: Obfuscation + network + process patterns → malware behaviour
  if (
    features.obfuscationScore > 0.7
    && features.suspiciousApiPatterns.includes("network")
    && features.suspiciousApiPatterns.includes("process")
  ) {
    score += 45;
    reasons.push("High obfuscation score with network+process API patterns — malware-like behaviour");
  }

  // Rule 4: High null-byte ratio + executable header → potential shellcode
  if (features.nullByteRatio > 0.3 && features.hasExecutableHeader) {
    score += 25;
    reasons.push("High null-byte ratio with executable header — potential shellcode or corrupted binary");
  }

  // Rule 5: Low printable ratio + not a known binary format
  const ext = extOf(filename);
  const isKnownBinary = BINARY_FORMAT_EXTENSIONS.has(ext) || isKnownBinaryMagic(content);
  if (features.printableRatio < 0.5 && !isKnownBinary) {
    score += 20;
    reasons.push("Low printable-char ratio in non-binary file — possible encoded payload");
  }

  // Rule 6: Executable masquerading as non-executable extension
  if (features.hasExecutableHeader && !isExecutableExtension(ext)) {
    score += 30;
    reasons.push("Executable magic bytes in a non-executable file extension — masquerading attempt");
  }

  // Rule 7: Very high entropy std dev in a text file → mixed content
  if (features.entropyStdDev > 2.5 && features.printableRatio > 0.8) {
    score += 10;
    reasons.push("High entropy variation across blocks in text file — possibly embedded binary blob");
  }

  // Rule 8: Large import count + process/file patterns
  if (features.importCount > 15 && features.suspiciousApiPatterns.length >= 3) {
    score += 15;
    reasons.push("High API import density across multiple categories");
  }

  // Rule 9: Obfuscation alone is suspicious
  if (features.obfuscationScore > 0.5 && score < 20) {
    score += 15;
    reasons.push("Moderate obfuscation detected (encoded strings, minified variable names)");
  }

  score = Math.min(100, Math.max(0, score));
  const verdict = verdictFromScore(score);
  const confidence = computeConfidence(score, reasons.length);

  if (reasons.length === 0) {
    reasons.push("No suspicious structural indicators detected");
  }

  return { verdict, confidence, features, reasons, riskScore: score };
}

// ─── AI-assisted classifier ─────────────────────────────────────────────────

export async function classifyFileWithAI(
  content: Buffer,
  filename: string,
  config: AIClassifierConfig,
): Promise<ClassificationResult> {
  const features = extractFeatures(content, filename);
  const headSample = extractPrintableHead(content, 2048);

  const prompt = buildAIPrompt(features, headSample, filename);

  try {
    const result = await callAI(config, prompt);
    if (result) {
      result.features = features;
      return result;
    }
  } catch {
    // AI unavailable — fall back silently
  }

  return classifyFile(content, filename);
}

// ─── Internal helpers ────────────────────────────────────────────────────────

function shannonEntropy(freq: Float64Array, total: number): number {
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / total;
    h -= p * Math.log2(p);
  }
  return h;
}

function blockEntropyStdDev(buf: Buffer, blockSize: number): number {
  const numBlocks = Math.floor(buf.length / blockSize);
  if (numBlocks < 2) return 0;

  const entropies: number[] = [];
  for (let b = 0; b < numBlocks; b++) {
    const offset = b * blockSize;
    const freq = new Float64Array(256);
    for (let i = 0; i < blockSize; i++) freq[buf[offset + i]]++;
    entropies.push(shannonEntropy(freq, blockSize));
  }

  const mean = entropies.reduce((a, b) => a + b, 0) / entropies.length;
  const variance = entropies.reduce((a, e) => a + (e - mean) ** 2, 0) / entropies.length;
  return Math.sqrt(variance);
}

function computeObfuscationScore(text: string): number {
  let signals = 0;
  let total = 0;

  // Signal 1: Single-char or very short variable names (minification proxy)
  const identifiers = text.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g) ?? [];
  if (identifiers.length > 20) {
    total++;
    const shortRatio = identifiers.filter(id => id.length <= 2).length / identifiers.length;
    if (shortRatio > 0.5) signals++;
  }

  // Signal 2: Hex / unicode escape sequences
  total++;
  const escapeCount = (text.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\u\{[0-9a-f]+\}/gi) ?? []).length;
  if (escapeCount > 10) signals++;

  // Signal 3: Base64-encoded strings (long alphanum blocks)
  total++;
  const b64Blocks = (text.match(/["'][A-Za-z0-9+/=]{40,}["']/g) ?? []).length;
  if (b64Blocks > 2) signals++;

  // Signal 4: String concatenation chains (obfuscation to avoid detection)
  total++;
  const concatChains = (text.match(/["'][^"']{1,3}["']\s*\+\s*["']/g) ?? []).length;
  if (concatChains > 5) signals++;

  // Signal 5: Extremely long lines (minified / packed)
  total++;
  const lines = text.split("\n");
  const longLines = lines.filter(l => l.length > 500).length;
  if (longLines > 0 && lines.length < 10) signals++;

  // Signal 6: High ratio of non-alphanumeric to alphanumeric
  total++;
  const alphaNum = (text.match(/[a-zA-Z0-9]/g) ?? []).length;
  const nonAlpha = text.length - alphaNum;
  if (text.length > 100 && nonAlpha / text.length > 0.55) signals++;

  return total > 0 ? signals / total : 0;
}

function isKnownBinaryMagic(buf: Buffer): boolean {
  return KNOWN_BINARY_MAGIC.some(
    (magic) => magic.every((b, i) => i < buf.length && buf[i] === b),
  );
}

function extOf(filename: string): string {
  const dot = filename.lastIndexOf(".");
  return dot === -1 ? "" : filename.slice(dot).toLowerCase();
}

const EXEC_EXTENSIONS = new Set([
  ".exe", ".dll", ".sys", ".scr", ".com",
  ".elf", ".bin", ".out",
  ".dylib", ".app",
]);

function isExecutableExtension(ext: string): boolean {
  return EXEC_EXTENSIONS.has(ext);
}

function verdictFromScore(score: number): ClassificationResult["verdict"] {
  if (score >= 50) return "malicious";
  if (score >= 20) return "suspicious";
  return "clean";
}

function computeConfidence(score: number, reasonCount: number): number {
  if (score >= 70) return Math.min(0.95, 0.7 + reasonCount * 0.05);
  if (score >= 50) return Math.min(0.85, 0.55 + reasonCount * 0.05);
  if (score >= 20) return Math.min(0.75, 0.45 + reasonCount * 0.05);
  return Math.min(0.9, 0.7 + (1 - score / 20) * 0.1);
}

function extractPrintableHead(buf: Buffer, maxBytes: number): string {
  const slice = buf.subarray(0, maxBytes);
  const chars: string[] = [];
  for (let i = 0; i < slice.length; i++) {
    const b = slice[i];
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) {
      chars.push(String.fromCharCode(b));
    }
  }
  return chars.join("");
}

function buildAIPrompt(features: FileFeatures, headSample: string, filename: string): string {
  return `You are a malware analyst. Classify this file as "clean", "suspicious", or "malicious".

Filename: ${filename}
Size: ${features.sizeBytes} bytes
Entropy: ${features.entropy.toFixed(3)} (std dev: ${features.entropyStdDev.toFixed(3)})
Printable ratio: ${(features.printableRatio * 100).toFixed(1)}%
Null byte ratio: ${(features.nullByteRatio * 100).toFixed(1)}%
High bit ratio: ${(features.highBitRatio * 100).toFixed(1)}%
Magic bytes: ${features.magicBytes}
Executable header: ${features.hasExecutableHeader}
Suspicious string count: ${features.suspiciousStringCount}
Import/API count: ${features.importCount}
API categories: ${features.suspiciousApiPatterns.join(", ") || "none"}
Obfuscation score: ${features.obfuscationScore.toFixed(2)}

First 2KB of printable content:
\`\`\`
${headSample}
\`\`\`

Respond with ONLY a JSON object (no markdown fencing):
{
  "verdict": "clean" | "suspicious" | "malicious",
  "confidence": 0.0-1.0,
  "reasons": ["reason1", "reason2"],
  "riskScore": 0-100
}`;
}

async function callAI(
  config: AIClassifierConfig,
  prompt: string,
): Promise<ClassificationResult | null> {
  const timeout = config.timeoutMs ?? 15_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(config.endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        model: config.model ?? "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.1,
        max_tokens: 256,
      }),
      signal: controller.signal,
    });

    if (!res.ok) return null;

    const json = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const raw = json.choices?.[0]?.message?.content?.trim();
    if (!raw) return null;

    const parsed = JSON.parse(raw) as {
      verdict?: string;
      confidence?: number;
      reasons?: string[];
      riskScore?: number;
    };

    if (!parsed.verdict || !["clean", "suspicious", "malicious"].includes(parsed.verdict)) {
      return null;
    }

    return {
      verdict: parsed.verdict as ClassificationResult["verdict"],
      confidence: typeof parsed.confidence === "number" ? parsed.confidence : 0.5,
      features: null as unknown as FileFeatures,
      reasons: Array.isArray(parsed.reasons) ? parsed.reasons : [],
      riskScore: typeof parsed.riskScore === "number" ? parsed.riskScore : 50,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Telegram Command & Message Handlers.
 *
 * Each handler receives a UnifiedMessage and returns a UnifiedResponse.
 * Registered with the MessageRouter at gateway startup.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { UnifiedMessage, UnifiedResponse, InlineButton } from "../common/types";
import type { MessageRouter } from "../common/router";

// ─── Branding ───────────────────────────────────────────────────────────────────

const LYRIE_LOGO = "🛡️";
const VERSION = "0.1.0";

// ─── /start ─────────────────────────────────────────────────────────────────────

async function handleStart(msg: UnifiedMessage): Promise<UnifiedResponse> {
  return {
    text: [
      `${LYRIE_LOGO} *Welcome to Lyrie Agent*`,
      "",
      "Your autonomous AI agent with built-in cybersecurity.",
      "",
      "I can help you with:",
      "• 🔍 Scanning URLs and files for threats",
      "• 🛡️ Protecting your devices",
      "• 🤖 AI-powered assistance",
      "• 📊 Real-time threat intelligence",
      "",
      "Powered by *OTT Cybersecurity LLC*",
      `Version ${VERSION}`,
    ].join("\n"),
    parseMode: "markdown",
    buttons: [
      [
        { text: "🔍 Scan a URL", callbackData: "scan" },
        { text: "🛡️ Protect", callbackData: "protect" },
      ],
      [
        { text: "📊 Status", callbackData: "status" },
        { text: "❓ Help", callbackData: "help" },
      ],
    ],
  };
}

// ─── /help ──────────────────────────────────────────────────────────────────────

async function handleHelp(msg: UnifiedMessage): Promise<UnifiedResponse> {
  return {
    text: [
      `${LYRIE_LOGO} *Lyrie Agent — Commands*`,
      "",
      "/start — Welcome & quick actions",
      "/help — Show this help menu",
      "/status — Agent & shield status",
      "/scan <url> — Scan a URL for threats",
      "/protect — Enable device protection",
      "/model — Current AI model info",
      "",
      "Or just send me a message — I'll use AI to help.",
      "",
      "_Lyrie.ai — Autonomous Cyber Operations_",
    ].join("\n"),
    parseMode: "markdown",
  };
}

// ─── /status ────────────────────────────────────────────────────────────────────

async function handleStatus(msg: UnifiedMessage): Promise<UnifiedResponse> {
  const uptime = process.uptime();
  const hours = Math.floor(uptime / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const mem = process.memoryUsage();
  const heapMB = (mem.heapUsed / 1024 / 1024).toFixed(1);

  return {
    text: [
      `${LYRIE_LOGO} *Lyrie Agent Status*`,
      "",
      `*Agent:* ✅ Online`,
      `*Uptime:* ${hours}h ${minutes}m`,
      `*Memory:* ${heapMB} MB`,
      `*Shield:* 🛡️ Active`,
      `*Threats Blocked:* 0`,
      `*Model:* Auto-routed`,
      "",
      `*Channel:* Telegram`,
      `*User:* ${msg.senderName} (${msg.senderId})`,
    ].join("\n"),
    parseMode: "markdown",
    buttons: [
      [
        { text: "🔄 Refresh", callbackData: "status" },
        { text: "📊 Detailed", callbackData: "status:detailed" },
      ],
    ],
  };
}

// ─── /scan ──────────────────────────────────────────────────────────────────────

async function handleScan(msg: UnifiedMessage, args: string[]): Promise<UnifiedResponse> {
  const url = args[0] || msg.command?.argv[0];

  if (!url) {
    return {
      text: [
        `${LYRIE_LOGO} *URL Scanner*`,
        "",
        "Usage: `/scan <url>`",
        "",
        "Example: `/scan https://suspicious-site.com`",
        "",
        "I'll check it against threat databases, analyze the content, and report back.",
      ].join("\n"),
      parseMode: "markdown",
    };
  }

  // Validate URL format
  try {
    new URL(url.startsWith("http") ? url : `https://${url}`);
  } catch {
    return {
      text: `⚠️ Invalid URL format: \`${url}\`\n\nPlease provide a valid URL.`,
      parseMode: "markdown",
    };
  }

  const normalizedUrl = url.startsWith("http") ? url : `https://${url}`;

  // Send initial "scanning" response (the bot will edit this later with results)
  return {
    text: [
      `${LYRIE_LOGO} *Scanning URL...*`,
      "",
      `🔗 \`${normalizedUrl}\``,
      "",
      "⏳ Checking threat databases...",
      "⏳ Analyzing SSL certificate...",
      "⏳ Checking domain reputation...",
      "⏳ Scanning for malware signatures...",
    ].join("\n"),
    parseMode: "markdown",
    extra: {
      // Flag for the bot to trigger an async scan and edit the message
      _action: "scan_url",
      _url: normalizedUrl,
    },
  };
}

// ─── /protect ───────────────────────────────────────────────────────────────────

async function handleProtect(msg: UnifiedMessage): Promise<UnifiedResponse> {
  return {
    text: [
      `${LYRIE_LOGO} *Device Protection*`,
      "",
      "Choose your protection level:",
      "",
      "🟢 *Basic* — Malware scanning, phishing protection",
      "🟡 *Standard* — Basic + network monitoring, DNS filtering",
      "🔴 *Maximum* — Standard + real-time file analysis, firewall rules",
    ].join("\n"),
    parseMode: "markdown",
    buttons: [
      [
        { text: "🟢 Basic", callbackData: "protect:basic" },
        { text: "🟡 Standard", callbackData: "protect:standard" },
        { text: "🔴 Maximum", callbackData: "protect:maximum" },
      ],
      [{ text: "📖 Learn More", url: "https://lyrie.ai/protect" }],
    ],
  };
}

// ─── /model ─────────────────────────────────────────────────────────────────────

async function handleModel(msg: UnifiedMessage, args: string[]): Promise<UnifiedResponse> {
  const models = [
    { id: "auto", name: "Auto-Route", desc: "Automatically picks the best model" },
    { id: "claude", name: "Claude Opus", desc: "Best for complex reasoning" },
    { id: "gpt5", name: "GPT-5.4", desc: "Best for coding" },
    { id: "gemini", name: "Gemini Pro", desc: "Best for multimodal" },
    { id: "local", name: "Local (Llama)", desc: "Private, on-device" },
  ];

  if (args.length > 0) {
    const selected = args[0].toLowerCase();
    const model = models.find((m) => m.id === selected);
    if (model) {
      return {
        text: `✅ Model switched to *${model.name}*\n\n_${model.desc}_`,
        parseMode: "markdown",
      };
    }
    return {
      text: `⚠️ Unknown model: \`${args[0]}\`\n\nUse /model to see available models.`,
      parseMode: "markdown",
    };
  }

  return {
    text: [
      `${LYRIE_LOGO} *AI Model Selection*`,
      "",
      `Current: *Auto-Route* (recommended)`,
      "",
      "Available models:",
      ...models.map((m) => `• *${m.name}* — ${m.desc}`),
    ].join("\n"),
    parseMode: "markdown",
    buttons: models.map((m) => [
      { text: `${m.id === "auto" ? "✅ " : ""}${m.name}`, callbackData: `model:${m.id}` },
    ]),
  };
}

// ─── Register All Handlers ──────────────────────────────────────────────────────

export function registerHandlers(router: MessageRouter): void {
  router.registerCommand("start", handleStart);
  router.registerCommand("help", handleHelp);
  router.registerCommand("status", handleStatus);
  router.registerCommand("scan", handleScan);
  router.registerCommand("protect", handleProtect);
  router.registerCommand("model", handleModel);

  console.log("  ✓ Registered 6 Telegram command handlers");
}

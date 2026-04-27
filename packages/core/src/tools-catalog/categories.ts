/**
 * Lyrie Tools Catalog — category descriptors.
 *
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import type { CategoryDescriptor, ToolCategory } from "./types";

export const CATEGORIES: ReadonlyArray<CategoryDescriptor> = [
  {
    id: "information-gathering",
    title: "Information Gathering",
    emoji: "🔍",
    description:
      "OSINT, recon, subdomain enumeration, port scanning, attack-surface discovery.",
  },
  {
    id: "wordlist",
    title: "Wordlist Generation",
    emoji: "📚",
    description: "Custom wordlist generators for password and parameter fuzzing.",
  },
  {
    id: "sql-injection",
    title: "SQL Injection",
    emoji: "🧩",
    description: "Detection and validation of SQL injection vulnerabilities.",
  },
  {
    id: "web-attack",
    title: "Web Attack",
    emoji: "🌐",
    description: "Crawlers, scanners, fuzzers, and template-engines for web testing.",
  },
  {
    id: "post-exploitation",
    title: "Post Exploitation",
    emoji: "🔧",
    description:
      "Authorized post-compromise tools — privilege-escalation enumeration, pivoting, C2 (consenting targets only).",
  },
  {
    id: "forensics",
    title: "Forensics",
    emoji: "🕵️",
    description: "Memory, disk, and binary forensics for incident response.",
  },
  {
    id: "exploit-framework",
    title: "Exploit Framework",
    emoji: "🧰",
    description: "Reproducible exploit development frameworks.",
  },
  {
    id: "reverse-engineering",
    title: "Reverse Engineering",
    emoji: "🔁",
    description: "Decompilers, disassemblers, and binary analysis platforms.",
  },
  {
    id: "xss",
    title: "Cross-Site Scripting",
    emoji: "💥",
    description: "XSS detection and validation.",
  },
  {
    id: "active-directory",
    title: "Active Directory",
    emoji: "🏢",
    description: "AD enumeration, Kerberos, and authorisation testing.",
  },
  {
    id: "cloud-security",
    title: "Cloud Security",
    emoji: "☁️",
    description: "AWS / GCP / Azure posture, IaC, and misconfiguration audit.",
  },
  {
    id: "mobile-security",
    title: "Mobile Security",
    emoji: "📱",
    description: "Mobile app static + dynamic analysis (iOS / Android).",
  },
  {
    id: "container-security",
    title: "Container Security",
    emoji: "🐳",
    description: "Container image, IaC, and Kubernetes audit.",
  },
  {
    id: "secrets",
    title: "Secret Scanning",
    emoji: "🔐",
    description: "Pre-commit + repo-wide credential discovery.",
  },
  {
    id: "fuzzing",
    title: "Fuzzing",
    emoji: "🎯",
    description: "Web parameter, directory, and content discovery fuzzers.",
  },
  {
    id: "password-cracking",
    title: "Password Cracking",
    emoji: "🔓",
    description: "Authorized password recovery — your hashes only.",
  },
  {
    id: "threat-intel",
    title: "Threat Intelligence",
    emoji: "📡",
    description: "CVE feeds, KEV catalogs, advisory enrichers.",
  },
  {
    id: "ssl-tls",
    title: "SSL / TLS",
    emoji: "🔒",
    description: "Certificate, cipher, and protocol audit.",
  },
  {
    id: "supply-chain",
    title: "Supply-Chain",
    emoji: "📦",
    description: "Dependency, SBOM, and supply-chain audit.",
  },
];

export const CATEGORY_BY_ID: ReadonlyMap<ToolCategory, CategoryDescriptor> = new Map(
  CATEGORIES.map((c) => [c.id, c]),
);

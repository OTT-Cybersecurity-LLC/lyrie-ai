#!/usr/bin/env bun
/**
 * Post (or update) a Lyrie pentest summary as a PR comment.
 *
 * Single-comment-per-PR: looks for an existing comment with our marker,
 * updates it instead of stacking duplicates.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { readFileSync } from "node:fs";

const args = parseArgs(process.argv.slice(2));
const token = process.env.GITHUB_TOKEN;
if (!token) {
  console.warn("::warning::No GITHUB_TOKEN; skipping PR comment.");
  process.exit(0);
}

const reportPath = args.report ?? "lyrie-runs/report.md";
const pr = args.pr;
const repo = args.repo;
if (!pr || !repo) {
  console.warn("::warning::Missing --pr or --repo; skipping PR comment.");
  process.exit(0);
}

const body =
  `<!-- lyrie-pentest-comment -->\n` +
  readFileSync(reportPath, "utf8");

const headers = {
  "Authorization": `Bearer ${token}`,
  "Accept": "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type": "application/json",
};

const listRes = await fetch(
  `https://api.github.com/repos/${repo}/issues/${pr}/comments?per_page=100`,
  { headers },
);
const comments = (await listRes.json()) as Array<{ id: number; body: string }>;
const existing = Array.isArray(comments)
  ? comments.find((c) => typeof c.body === "string" && c.body.includes("lyrie-pentest-comment"))
  : undefined;

if (existing) {
  const r = await fetch(
    `https://api.github.com/repos/${repo}/issues/comments/${existing.id}`,
    { method: "PATCH", headers, body: JSON.stringify({ body }) },
  );
  if (!r.ok) console.warn(`::warning::PR comment update failed: ${r.status}`);
  else console.log("Updated existing Lyrie PR comment.");
} else {
  const r = await fetch(
    `https://api.github.com/repos/${repo}/issues/${pr}/comments`,
    { method: "POST", headers, body: JSON.stringify({ body }) },
  );
  if (!r.ok) console.warn(`::warning::PR comment create failed: ${r.status}`);
  else console.log("Created Lyrie PR comment.");
}

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const k = a.slice(2);
      const v = argv[i + 1] ?? "";
      out[k] = v;
      i++;
    }
  }
  return out;
}

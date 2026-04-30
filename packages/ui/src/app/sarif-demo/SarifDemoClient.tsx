"use client";

import { useEffect, useRef, useState } from "react";
import { SarifViewer } from "@/sarif-viewer";

// ---------------------------------------------------------------------------
// Sample SARIF — realistic lyrie scan output
// ---------------------------------------------------------------------------
const SAMPLE_SARIF = JSON.stringify(
  {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Lyrie",
            version: "0.1.0",
            rules: [
              {
                id: "SQL001",
                name: "SqlInjection",
                shortDescription: { text: "Unsanitised user input in SQL query" },
                defaultConfiguration: { level: "error" },
                helpUri: "https://lyrie.ai/rules/SQL001",
              },
              {
                id: "XSS002",
                name: "CrossSiteScripting",
                shortDescription: { text: "Reflected XSS via unescaped template variable" },
                defaultConfiguration: { level: "warning" },
                helpUri: "https://lyrie.ai/rules/XSS002",
              },
              {
                id: "CSRF003",
                name: "CrossSiteRequestForgery",
                shortDescription: { text: "Endpoint missing CSRF token validation" },
                defaultConfiguration: { level: "warning" },
                helpUri: "https://lyrie.ai/rules/CSRF003",
              },
              {
                id: "INFO001",
                name: "SensitiveDataExposure",
                shortDescription: { text: "Stack trace or secret leaked in HTTP response" },
                defaultConfiguration: { level: "note" },
                helpUri: "https://lyrie.ai/rules/INFO001",
              },
            ],
          },
        },
        results: [
          {
            ruleId: "SQL001",
            level: "error",
            message: { text: "Raw user input concatenated into SQL query without parameterisation." },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/auth/login.ts" },
                  region: { startLine: 42, startColumn: 12 },
                },
              },
            ],
          },
          {
            ruleId: "SQL001",
            level: "error",
            message: { text: "Dynamic table name built from query parameter — SQLI possible." },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/search/query.ts" },
                  region: { startLine: 17, startColumn: 5 },
                },
              },
            ],
          },
          {
            ruleId: "XSS002",
            level: "warning",
            message: { text: "User-controlled `name` rendered without HTML encoding in email template." },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/views/profile.ts" },
                  region: { startLine: 88, startColumn: 24 },
                },
              },
            ],
          },
          {
            ruleId: "CSRF003",
            level: "warning",
            message: { text: "POST /api/settings accepts requests with no CSRF token." },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/api/settings.ts" },
                  region: { startLine: 14 },
                },
              },
            ],
          },
          {
            ruleId: "INFO001",
            level: "note",
            message: {
              text: "Express error handler serialises full Error object including stack into JSON response.",
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/middleware/error-handler.ts" },
                  region: { startLine: 31 },
                },
              },
            ],
          },
        ],
      },
    ],
  },
  null,
  2
);

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function SarifDemoClient() {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewerRef = useRef<SarifViewer | null>(null);
  const [customSarif, setCustomSarif] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<"sample" | "custom" | null>(null);

  // Mount viewer + load sample on init
  useEffect(() => {
    if (!containerRef.current) return;
    viewerRef.current = new SarifViewer(containerRef.current);
    try {
      viewerRef.current.load(SAMPLE_SARIF);
      setLoaded("sample");
      setError(null);
    } catch (e: any) {
      setError(e.message);
    }
  }, []);

  function handleLoadSample() {
    if (!viewerRef.current) return;
    setCustomSarif("");
    setError(null);
    try {
      viewerRef.current.load(SAMPLE_SARIF);
      setLoaded("sample");
    } catch (e: any) {
      setError(e.message);
    }
  }

  function handleLoadCustom() {
    if (!viewerRef.current || !customSarif.trim()) return;
    setError(null);
    try {
      viewerRef.current.load(customSarif.trim());
      setLoaded("custom");
    } catch (e: any) {
      setError(e.message);
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-8">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">
          🛡 Lyrie SARIF Viewer — Demo
        </h1>
        <p className="text-gray-400 text-sm">
          Framework-free SARIF 2.1.0 renderer. Paste your SARIF JSON below or
          load the built-in sample.
        </p>
      </header>

      {/* Controls */}
      <div className="mb-6 flex flex-col gap-4">
        <div className="flex gap-3 items-center flex-wrap">
          <button
            onClick={handleLoadSample}
            className="px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm font-medium transition-colors"
          >
            Load sample SARIF
          </button>
          <button
            onClick={handleLoadCustom}
            disabled={!customSarif.trim()}
            className="px-4 py-2 bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-white rounded text-sm font-medium transition-colors"
          >
            Load custom SARIF
          </button>
          {loaded && (
            <span className="text-xs text-gray-500">
              Showing: {loaded === "sample" ? "built-in sample" : "custom input"}
            </span>
          )}
        </div>

        <textarea
          value={customSarif}
          onChange={(e) => setCustomSarif(e.target.value)}
          placeholder='Paste SARIF 2.1.0 JSON here, e.g. {"version":"2.1.0","runs":[...]}'
          className="w-full h-32 bg-gray-900 border border-gray-700 rounded p-3 text-xs font-mono text-gray-300 placeholder-gray-600 resize-y focus:outline-none focus:border-blue-500"
        />

        {error && (
          <div className="bg-red-950 border border-red-800 rounded px-4 py-2 text-red-300 text-sm">
            ⚠ {error}
          </div>
        )}
      </div>

      {/* Viewer output */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <style>{`
          .sarif-run { margin-bottom: 1.5rem; }
          .sarif-run h2 {
            font-size: 1rem;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #374151;
          }
          .sarif-group {
            margin-bottom: 0.5rem;
            border: 1px solid #374151;
            border-radius: 6px;
            overflow: hidden;
          }
          .sarif-group summary {
            padding: 0.6rem 0.9rem;
            cursor: pointer;
            background: #1f2937;
            user-select: none;
            font-size: 0.85rem;
            list-style: none;
          }
          .sarif-group summary::-webkit-details-marker { display: none; }
          .sarif-group[open] summary { border-bottom: 1px solid #374151; }
          .sarif-badge { font-weight: 700; font-size: 0.75rem; }
          .sarif-count { color: #9ca3af; font-size: 0.75rem; }
          .sarif-desc { color: #9ca3af; font-size: 0.8rem; }
          .sarif-help-link { color: #60a5fa; font-size: 0.75rem; margin-left: 0.25rem; }
          .sarif-results {
            list-style: none;
            margin: 0;
            padding: 0.5rem 0.9rem;
          }
          .sarif-result {
            padding: 0.35rem 0;
            font-size: 0.8rem;
            color: #d1d5db;
            border-bottom: 1px solid #1f2937;
          }
          .sarif-result:last-child { border-bottom: none; }
          .sarif-location {
            background: #111827;
            color: #a78bfa;
            padding: 0.1rem 0.35rem;
            border-radius: 3px;
            font-size: 0.75rem;
            font-family: monospace;
            margin-right: 0.25rem;
          }
        `}</style>
        <div ref={containerRef} />
      </div>

      <footer className="mt-8 text-xs text-gray-600">
        Route: <code>/sarif-demo</code> — uses{" "}
        <code>packages/ui/src/sarif-viewer/SarifViewer.ts</code> directly.
      </footer>
    </div>
  );
}

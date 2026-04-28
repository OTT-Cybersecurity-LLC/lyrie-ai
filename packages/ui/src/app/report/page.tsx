"use client";
/**
 * Lyrie Scan Report Page
 *
 * URL patterns:
 *   /report?data=<base64-encoded-sarif>   — inline data
 *   /report?url=<sarif-url>               — remote fetch
 *   /report                               — file upload (drag-and-drop / picker)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import React, { useEffect, useState, useCallback, useRef } from "react";
import { SarifViewer } from "@/sarif-viewer/SarifViewer";
import type { SarifDocument } from "@/sarif-viewer/types";

type LoadState =
  | { status: "idle" }
  | { status: "loading"; hint: string }
  | { status: "ready"; doc: SarifDocument; source: string }
  | { status: "error"; message: string };

function decodeBase64Sarif(b64: string): SarifDocument | null {
  try {
    const json = atob(b64);
    return JSON.parse(json) as SarifDocument;
  } catch {
    return null;
  }
}

function DropZone({ onFile }: { onFile: (content: string) => void }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const readFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      if (text) onFile(text);
    };
    reader.readAsText(file);
  };

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) readFile(file);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    []
  );

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current?.click()}
      className={`
        border-2 border-dashed rounded-2xl p-16 text-center cursor-pointer transition-colors
        ${dragging ? "border-blue-500 bg-blue-500/10" : "border-white/20 hover:border-white/40"}
      `}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".sarif,.json"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) readFile(file);
        }}
      />
      <div className="text-4xl mb-4">📄</div>
      <p className="text-white font-semibold mb-1">Drop a SARIF file here</p>
      <p className="text-sm text-gray-500">or click to browse — accepts .sarif / .json</p>
    </div>
  );
}

export default function ReportPage() {
  const [state, setState] = useState<LoadState>({ status: "idle" });

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const dataParam = params.get("data");
    const urlParam = params.get("url");

    if (dataParam) {
      setState({ status: "loading", hint: "Decoding SARIF data…" });
      const doc = decodeBase64Sarif(dataParam);
      if (doc) {
        setState({ status: "ready", doc, source: "URL data parameter" });
      } else {
        setState({ status: "error", message: "Failed to decode SARIF from ?data= parameter." });
      }
      return;
    }

    if (urlParam) {
      setState({ status: "loading", hint: `Fetching ${urlParam}…` });
      fetch(urlParam)
        .then((r) => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          return r.json();
        })
        .then((doc: SarifDocument) => {
          setState({ status: "ready", doc, source: urlParam });
        })
        .catch((err: unknown) => {
          setState({ status: "error", message: `Failed to fetch SARIF: ${String(err)}` });
        });
    }
  }, []);

  const handleUploadedFile = useCallback((content: string) => {
    try {
      const doc = JSON.parse(content) as SarifDocument;
      setState({ status: "ready", doc, source: "uploaded file" });
    } catch {
      setState({ status: "error", message: "File does not appear to be valid JSON/SARIF." });
    }
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {/* Header */}
      <header className="border-b border-white/10 px-6 py-4 flex items-center gap-3">
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-sm">
          🛡
        </div>
        <h1 className="text-base font-semibold text-white">Lyrie Scan Report</h1>
        {state.status === "ready" && (
          <span className="text-xs text-gray-500 ml-2">Source: {state.source}</span>
        )}
      </header>

      {/* Body */}
      <main className="flex-1 max-w-5xl mx-auto w-full px-6 py-8">
        {state.status === "idle" && (
          <div className="space-y-6">
            <p className="text-sm text-gray-400">
              Load a SARIF report by uploading a file, or pass{" "}
              <code className="bg-white/10 px-1.5 py-0.5 rounded text-xs">?data=&lt;base64&gt;</code> or{" "}
              <code className="bg-white/10 px-1.5 py-0.5 rounded text-xs">?url=&lt;sarif-url&gt;</code> in the URL.
            </p>
            <DropZone onFile={handleUploadedFile} />
          </div>
        )}

        {state.status === "loading" && (
          <div className="flex items-center justify-center py-20 text-gray-400 text-sm gap-3">
            <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" strokeOpacity="0.25" />
              <path d="M12 2a10 10 0 0 1 10 10" />
            </svg>
            {state.hint}
          </div>
        )}

        {state.status === "error" && (
          <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-5 py-4 text-red-300 text-sm space-y-3">
            <p className="font-semibold">Failed to load SARIF report</p>
            <p>{state.message}</p>
            <button
              onClick={() => setState({ status: "idle" })}
              className="text-xs underline text-red-400 hover:text-red-300"
            >
              Try uploading a file instead
            </button>
          </div>
        )}

        {state.status === "ready" && <SarifViewer sarifData={state.doc} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 px-6 py-4 text-center text-xs text-gray-600">
        Powered by{" "}
        <a
          href="https://github.com/overthetopseo/lyrie-agent"
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-500 hover:text-gray-300 transition-colors"
        >
          Lyrie Agent ↗
        </a>
      </footer>
    </div>
  );
}

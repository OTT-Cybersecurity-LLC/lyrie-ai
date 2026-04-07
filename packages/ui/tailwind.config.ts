import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        lyrie: {
          bg: "#0a0a1a",
          surface: "#111127",
          card: "#16163a",
          border: "#1e1e4a",
          accent: "#4f46e5",
          "accent-light": "#6366f1",
          "accent-glow": "#818cf8",
          green: "#22c55e",
          red: "#ef4444",
          amber: "#f59e0b",
          cyan: "#06b6d4",
          text: "#e2e8f0",
          "text-dim": "#94a3b8",
          "text-muted": "#64748b",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      boxShadow: {
        glow: "0 0 20px rgba(79, 70, 229, 0.3)",
        "glow-lg": "0 0 40px rgba(79, 70, 229, 0.4)",
        "glow-green": "0 0 20px rgba(34, 197, 94, 0.3)",
        "glow-red": "0 0 20px rgba(239, 68, 68, 0.3)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanLine 4s linear infinite",
        "shield-rotate": "shieldRotate 8s linear infinite",
      },
      keyframes: {
        scanLine: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        shieldRotate: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
      },
    },
  },
  plugins: [],
};
export default config;

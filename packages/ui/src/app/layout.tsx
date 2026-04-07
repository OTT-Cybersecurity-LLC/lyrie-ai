import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";
import { Header } from "@/components/header";

export const metadata: Metadata = {
  title: "Lyrie Agent — Command Center",
  description: "Autonomous Agent Control & Cyber Defense Platform",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="font-sans antialiased bg-lyrie-bg text-lyrie-text min-h-screen">
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <div className="flex-1 flex flex-col overflow-hidden">
            <Header />
            <main className="flex-1 overflow-y-auto p-6 grid-bg">
              {children}
            </main>
            <footer className="border-t border-lyrie-border px-6 py-3 text-xs text-lyrie-text-muted flex items-center justify-between">
              <span>© 2026 OTT Cybersecurity LLC. All rights reserved.</span>
              <span className="font-mono text-lyrie-accent">Lyrie Agent v0.1.0</span>
            </footer>
          </div>
        </div>
      </body>
    </html>
  );
}

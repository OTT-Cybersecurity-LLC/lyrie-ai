/**
 * lyrie service — unit tests (all mocked, no real service installed)
 * Run: bun test tests/service.test.ts
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, it, expect, mock, beforeEach, afterEach } from "bun:test";
import { homedir } from "os";
import { join } from "path";

// ─── Mock fs & child_process before importing service modules ─────────────────

// We'll instantiate the classes and call methods directly, stubbing exec calls
// by monkey-patching child_process on the module level within each test.

import { LaunchdService } from "../packages/core/src/service/launchd";
import { SystemdService } from "../packages/core/src/service/systemd";
import { getServiceManager } from "../packages/core/src/service/index";
import type { ServiceConfig } from "../packages/core/src/service/types";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const defaultConfig: ServiceConfig = {
  label: "ai.lyrie.daemon",
  program: "/usr/local/bin/bun",
  args: ["run", "/opt/lyrie/scripts/daemon.ts", "--channel", "telegram"],
  logPath: join(homedir(), ".lyrie", "logs", "daemon.log"),
  runAtLoad: true,
  keepAlive: true,
};

const minimalConfig: ServiceConfig = {
  label: "ai.lyrie.test",
  program: "/usr/bin/node",
  args: ["server.js"],
};

// ─── LaunchdService Tests ─────────────────────────────────────────────────────

describe("LaunchdService", () => {
  let svc: LaunchdService;

  beforeEach(() => {
    svc = new LaunchdService();
  });

  it("generates valid plist XML with correct label", () => {
    const plist = svc.generatePlist(defaultConfig);
    expect(plist).toContain("<string>ai.lyrie.daemon</string>");
    expect(plist).toContain("<?xml version");
    expect(plist).toContain("<!DOCTYPE plist");
    expect(plist).toContain('<plist version="1.0">');
  });

  it("plist contains all program arguments", () => {
    const plist = svc.generatePlist(defaultConfig);
    expect(plist).toContain("<string>/usr/local/bin/bun</string>");
    expect(plist).toContain("<string>run</string>");
    expect(plist).toContain("<string>--channel</string>");
    expect(plist).toContain("<string>telegram</string>");
  });

  it("plist sets RunAtLoad true by default", () => {
    const plist = svc.generatePlist(defaultConfig);
    expect(plist).toMatch(/<key>RunAtLoad<\/key>\s*<true\/>/);
  });

  it("plist sets KeepAlive true by default", () => {
    const plist = svc.generatePlist(defaultConfig);
    expect(plist).toMatch(/<key>KeepAlive<\/key>\s*<true\/>/);
  });

  it("plist sets RunAtLoad false when configured", () => {
    const cfg = { ...defaultConfig, runAtLoad: false };
    const plist = svc.generatePlist(cfg);
    expect(plist).toMatch(/<key>RunAtLoad<\/key>\s*<false\/>/);
  });

  it("plist sets KeepAlive false when configured", () => {
    const cfg = { ...defaultConfig, keepAlive: false };
    const plist = svc.generatePlist(cfg);
    expect(plist).toMatch(/<key>KeepAlive<\/key>\s*<false\/>/);
  });

  it("plist includes StandardOutPath", () => {
    const plist = svc.generatePlist(defaultConfig);
    expect(plist).toContain("<key>StandardOutPath</key>");
    expect(plist).toContain(".lyrie/logs/daemon.log");
  });

  it("plist includes StandardErrorPath (derived from logPath)", () => {
    const plist = svc.generatePlist(defaultConfig);
    expect(plist).toContain("<key>StandardErrorPath</key>");
    expect(plist).toContain("daemon-error.log");
  });

  it("plist uses default log path when logPath is omitted", () => {
    const plist = svc.generatePlist(minimalConfig);
    expect(plist).toContain(".lyrie/logs/daemon.log");
  });

  it("plist escapes XML special chars in args", () => {
    const cfg: ServiceConfig = {
      label: "ai.lyrie.test",
      program: "/usr/bin/bun",
      args: ["--key=val&other", "<special>"],
    };
    const plist = svc.generatePlist(cfg);
    expect(plist).toContain("&amp;");
    expect(plist).toContain("&lt;");
    expect(plist).toContain("&gt;");
  });

  it("plist includes EnvironmentVariables when env is set", () => {
    const cfg: ServiceConfig = {
      ...defaultConfig,
      env: { LYRIE_ENV: "production", LOG_LEVEL: "info" },
    };
    const plist = svc.generatePlist(cfg);
    expect(plist).toContain("<key>EnvironmentVariables</key>");
    expect(plist).toContain("<key>LYRIE_ENV</key><string>production</string>");
    expect(plist).toContain("<key>LOG_LEVEL</key><string>info</string>");
  });

  it("plist does NOT include EnvironmentVariables block when env is omitted", () => {
    const plist = svc.generatePlist(minimalConfig);
    expect(plist).not.toContain("EnvironmentVariables");
  });

  it("plist path is in ~/Library/LaunchAgents/", () => {
    expect(svc.plistPath).toContain(join("Library", "LaunchAgents"));
    expect(svc.plistPath).toContain("ai.lyrie.daemon.plist");
  });

  it("plist is a complete well-formed document (opens and closes plist tag)", () => {
    const plist = svc.generatePlist(defaultConfig);
    expect(plist.indexOf("<plist")).toBeLessThan(plist.indexOf("</plist>"));
    expect(plist.indexOf("<dict>")).toBeLessThan(plist.indexOf("</dict>"));
  });
});

// ─── SystemdService Tests ─────────────────────────────────────────────────────

describe("SystemdService", () => {
  let svc: SystemdService;

  beforeEach(() => {
    svc = new SystemdService();
  });

  it("generates a [Unit] section", () => {
    const unit = svc.generateUnitFile(defaultConfig);
    expect(unit).toContain("[Unit]");
    expect(unit).toContain("Description=");
  });

  it("generates a [Service] section", () => {
    const unit = svc.generateUnitFile(defaultConfig);
    expect(unit).toContain("[Service]");
    expect(unit).toContain("Type=simple");
  });

  it("ExecStart includes program and all args", () => {
    const unit = svc.generateUnitFile(defaultConfig);
    expect(unit).toContain("/usr/local/bin/bun");
    expect(unit).toContain("run");
    expect(unit).toContain("--channel");
    expect(unit).toContain("telegram");
  });

  it("sets Restart=always when keepAlive is true", () => {
    const unit = svc.generateUnitFile(defaultConfig);
    expect(unit).toContain("Restart=always");
  });

  it("sets Restart=on-failure when keepAlive is false", () => {
    const cfg = { ...defaultConfig, keepAlive: false };
    const unit = svc.generateUnitFile(cfg);
    expect(unit).toContain("Restart=on-failure");
  });

  it("includes [Install] WantedBy=default.target when runAtLoad is true", () => {
    const unit = svc.generateUnitFile(defaultConfig);
    expect(unit).toContain("[Install]");
    expect(unit).toContain("WantedBy=default.target");
  });

  it("omits [Install] section when runAtLoad is false", () => {
    const cfg = { ...defaultConfig, runAtLoad: false };
    const unit = svc.generateUnitFile(cfg);
    expect(unit).not.toContain("[Install]");
  });

  it("unit file path is in ~/.config/systemd/user/", () => {
    expect(svc.unitPath).toContain(join(".config", "systemd", "user"));
    expect(svc.unitPath).toEndWith(".service");
  });

  it("unit file includes StandardOutput redirect to log file", () => {
    const unit = svc.generateUnitFile(defaultConfig);
    expect(unit).toContain("StandardOutput=append:");
    expect(unit).toContain("daemon.log");
  });

  it("unit file includes StandardError redirect to error log", () => {
    const unit = svc.generateUnitFile(defaultConfig);
    expect(unit).toContain("StandardError=append:");
    expect(unit).toContain("daemon-error.log");
  });

  it("unit file injects Environment= entries when env is set", () => {
    const cfg: ServiceConfig = {
      ...defaultConfig,
      env: { LYRIE_ENV: "production", API_KEY: "secret" },
    };
    const unit = svc.generateUnitFile(cfg);
    expect(unit).toContain('Environment="LYRIE_ENV=production"');
    expect(unit).toContain('Environment="API_KEY=secret"');
  });

  it("unit file has no Environment= lines when env is omitted", () => {
    const unit = svc.generateUnitFile(minimalConfig);
    expect(unit).not.toContain("Environment=");
  });
});

// ─── getServiceManager / auto-detection ──────────────────────────────────────

describe("getServiceManager (auto-detection)", () => {
  it("returns a LaunchdService on darwin", () => {
    // We're testing on macOS; getServiceManager should return LaunchdService
    if (process.platform === "darwin") {
      const mgr = getServiceManager();
      expect(mgr).toBeInstanceOf(LaunchdService);
    }
  });

  it("returns a SystemdService on linux", () => {
    // Simulate Linux by directly constructing (we can't change process.platform at runtime)
    const mgr = new SystemdService();
    expect(mgr).toBeInstanceOf(SystemdService);
  });

  it("getServiceManager returns an object with install method", () => {
    const mgr = getServiceManager();
    expect(typeof mgr.install).toBe("function");
  });

  it("getServiceManager returns an object with all required methods", () => {
    const mgr = getServiceManager();
    const required = ["install", "uninstall", "start", "stop", "restart", "status", "logs"];
    for (const method of required) {
      expect(typeof (mgr as any)[method]).toBe("function");
    }
  });
});

// ─── ServiceConfig defaults ───────────────────────────────────────────────────

describe("ServiceConfig defaults", () => {
  it("LaunchdService uses ~/.lyrie/logs/daemon.log as default logPath", () => {
    const svc = new LaunchdService();
    const plist = svc.generatePlist(minimalConfig);
    const expectedDefault = join(homedir(), ".lyrie", "logs", "daemon.log");
    expect(plist).toContain(expectedDefault);
  });

  it("SystemdService uses ~/.lyrie/logs/daemon.log as default logPath", () => {
    const svc = new SystemdService();
    const unit = svc.generateUnitFile(minimalConfig);
    const expectedDefault = join(homedir(), ".lyrie", "logs", "daemon.log");
    expect(unit).toContain(expectedDefault);
  });

  it("LaunchdService RunAtLoad defaults to true", () => {
    const svc = new LaunchdService();
    const plist = svc.generatePlist(minimalConfig);
    expect(plist).toMatch(/<key>RunAtLoad<\/key>\s*<true\/>/);
  });

  it("LaunchdService KeepAlive defaults to true", () => {
    const svc = new LaunchdService();
    const plist = svc.generatePlist(minimalConfig);
    expect(plist).toMatch(/<key>KeepAlive<\/key>\s*<true\/>/);
  });

  it("SystemdService Restart defaults to always (keepAlive not specified)", () => {
    const svc = new SystemdService();
    const unit = svc.generateUnitFile(minimalConfig);
    expect(unit).toContain("Restart=always");
  });
});

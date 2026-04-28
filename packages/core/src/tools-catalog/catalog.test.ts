/**
 * Lyrie Tools Catalog — unit tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import { describe, expect, test } from "bun:test";

import {
  BUILTIN_TOOLS,
  BUILTIN_TOOL_COUNT,
  CATALOG_SIGNATURE,
  CATALOG_VERSION,
  CATEGORIES,
  CATEGORY_BY_ID,
  ToolsCatalog,
  type ToolDefinition,
} from "./index";

function makeFakeTool(over: Partial<ToolDefinition> = {}): ToolDefinition {
  return {
    id: "fake-tool",
    name: "Fake Tool",
    description: "A test tool used by the unit suite.",
    homepage: "https://lyrie.ai",
    license: "MIT",
    category: "information-gathering",
    tags: ["scanner"],
    install: { kind: "system", command: "true", detect: "true" },
    supportedOS: ["linux", "macos"],
    intents: ["fake test intent"],
    ...over,
  };
}

// ─── Catalog hygiene ────────────────────────────────────────────────────────

describe("Lyrie Tools Catalog hygiene", () => {
  test("ships at least 35 vetted tools", () => {
    expect(BUILTIN_TOOL_COUNT).toBeGreaterThanOrEqual(35);
  });

  test("every builtin tool has unique id, name, description, homepage, install", () => {
    const ids = new Set<string>();
    for (const tool of BUILTIN_TOOLS) {
      expect(tool.id).toMatch(/^[a-z0-9-]+$/);
      expect(ids.has(tool.id)).toBe(false);
      ids.add(tool.id);
      expect(tool.name.length).toBeGreaterThan(0);
      expect(tool.description.length).toBeGreaterThan(10);
      expect(tool.description.length).toBeLessThan(180);
      expect(tool.homepage.startsWith("https://")).toBe(true);
      expect(tool.install.command.length).toBeGreaterThan(0);
      expect(tool.install.detect.length).toBeGreaterThan(0);
      expect(tool.intents.length).toBeGreaterThan(0);
      expect(tool.supportedOS.length).toBeGreaterThan(0);
    }
  });

  test("every builtin tool category exists in CATEGORIES", () => {
    for (const tool of BUILTIN_TOOLS) {
      expect(CATEGORY_BY_ID.has(tool.category)).toBe(true);
    }
  });

  test("BLACKLISTED categories never appear", () => {
    // Lyrie deliberately excludes these abuse-prone categories.
    const banned = new Set(["phishing", "ddos", "rat", "wireless-deauth", "anonymity"]);
    for (const tool of BUILTIN_TOOLS) {
      expect(banned.has(tool.category as unknown as string)).toBe(false);
    }
  });

  test("CATALOG_VERSION + CATALOG_SIGNATURE are Lyrie-stamped", () => {
    expect(CATALOG_VERSION).toMatch(/^lyrie-tools-catalog-/);
    expect(CATALOG_SIGNATURE).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });

  test("CATEGORIES has 19 well-formed entries", () => {
    expect(CATEGORIES.length).toBe(19);
    for (const cat of CATEGORIES) {
      expect(cat.id.length).toBeGreaterThan(0);
      expect(cat.title.length).toBeGreaterThan(0);
      expect(cat.description.length).toBeGreaterThan(10);
      expect(cat.emoji.length).toBeGreaterThan(0);
    }
  });
});

// ─── Catalog mechanics ─────────────────────────────────────────────────────

describe("ToolsCatalog mechanics", () => {
  test("constructor populates id / category / tag indices", () => {
    const cat = new ToolsCatalog();
    expect(cat.list().length).toBe(BUILTIN_TOOL_COUNT);
    expect(cat.get("nuclei")?.name).toBe("Nuclei");
    expect(cat.byCategoryList("web-attack").length).toBeGreaterThan(0);
    expect(cat.byTagList("scanner").length).toBeGreaterThan(0);
  });

  test("register + unregister are idempotent and update indices", () => {
    const cat = new ToolsCatalog([]);
    expect(cat.list().length).toBe(0);
    cat.register(makeFakeTool());
    expect(cat.list().length).toBe(1);
    cat.register(makeFakeTool({ description: "Updated" }));
    expect(cat.list().length).toBe(1);
    expect(cat.get("fake-tool")?.description).toBe("Updated");

    expect(cat.unregister("fake-tool")).toBe(true);
    expect(cat.list().length).toBe(0);
    expect(cat.byCategoryList("information-gathering").length).toBe(0);
    expect(cat.byTagList("scanner").length).toBe(0);
    expect(cat.unregister("fake-tool")).toBe(false);
  });

  test("signature + version are stamped", () => {
    const cat = new ToolsCatalog();
    expect(cat.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
    expect(cat.version).toBe(CATALOG_VERSION);
  });
});

// ─── Search ─────────────────────────────────────────────────────────────────

describe("ToolsCatalog.search", () => {
  const cat = new ToolsCatalog();

  test("returns tools matching the query", () => {
    const r = cat.search("nuclei");
    expect(r[0].id).toBe("nuclei");
  });

  test("scores name + intents higher than tag-only matches", () => {
    const r = cat.search("subdomain");
    expect(r.length).toBeGreaterThanOrEqual(2);
    expect(["subfinder", "amass"]).toContain(r[0].id);
  });

  test("returns [] for empty / whitespace-only", () => {
    expect(cat.search("")).toEqual([]);
    expect(cat.search("   ")).toEqual([]);
  });

  test("returns [] for nonsense", () => {
    expect(cat.search("xyzzy-no-match-12345")).toEqual([]);
  });
});

// ─── Recommend ──────────────────────────────────────────────────────────────

describe("ToolsCatalog.recommend", () => {
  const cat = new ToolsCatalog();

  test("'I want to scan a network' suggests nmap-class tools first", () => {
    const r = cat.recommend("I want to scan a network for open ports");
    expect(r.length).toBeGreaterThan(0);
    const ids = r.map((t) => t.id);
    expect(ids).toContain("nmap");
  });

  test("'find subdomains' surfaces subfinder/amass", () => {
    const r = cat.recommend("find subdomains for example.com");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => id === "subfinder" || id === "amass")).toBe(true);
  });

  test("'audit aws' surfaces a cloud-security tool", () => {
    const r = cat.recommend("audit my aws account");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => ["prowler", "scoutsuite"].includes(id))).toBe(true);
  });

  test("'find leaked credentials in git' surfaces secret scanners", () => {
    const r = cat.recommend("find leaked credentials in git");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => id === "gitleaks" || id === "trufflehog")).toBe(true);
  });

  test("'scan an android app' surfaces mobile tools", () => {
    const r = cat.recommend("scan an android app for vulnerabilities");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => ["mobsf", "frida", "objection"].includes(id))).toBe(true);
  });

  test("'kerberos password spray' surfaces ad tools", () => {
    const r = cat.recommend("kerberos password spray");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => ["kerbrute", "netexec", "impacket"].includes(id))).toBe(true);
  });

  test("limit option caps the result count", () => {
    const r = cat.recommend("scan", 3);
    expect(r.length).toBeLessThanOrEqual(3);
  });

  test("returns [] for empty intent", () => {
    expect(cat.recommend("")).toEqual([]);
    expect(cat.recommend("   ")).toEqual([]);
  });

  // ─── New cloud + mobile phrases (#43) ──────────────────────────────────

  test("'scan s3 bucket permissions' surfaces prowler/scoutsuite", () => {
    const r = cat.recommend("scan s3 bucket permissions");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => ["prowler", "scoutsuite"].includes(id))).toBe(true);
  });

  test("'kubernetes security' surfaces trivy/nuclei", () => {
    const r = cat.recommend("kubernetes security audit");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => ["trivy", "nuclei"].includes(id))).toBe(true);
  });

  test("'hook mobile app' surfaces frida/objection", () => {
    const r = cat.recommend("hook mobile app at runtime");
    const ids = r.map((t) => t.id);
    expect(ids.some((id) => ["frida", "objection"].includes(id))).toBe(true);
  });
});

// ─── Install detection (limited — depends on the test host) ────────────────

describe("ToolsCatalog.isInstalled", () => {
  const cat = new ToolsCatalog();

  test("a tool with a fake detector is reported missing", () => {
    const fake = makeFakeTool({
      id: "ghost-tool",
      install: {
        kind: "system",
        command: "echo nope",
        detect: "lyrie-ghost-detector-9b8a7-NEVER-EXISTS",
      },
    });
    cat.register(fake);
    expect(cat.isInstalled(fake).installed).toBe(false);
    cat.unregister("ghost-tool");
  });
});

// ─── Stats ──────────────────────────────────────────────────────────────────

describe("ToolsCatalog.stats", () => {
  const cat = new ToolsCatalog();
  const stats = cat.stats();

  test("totals match the builtin count", () => {
    expect(stats.total).toBe(BUILTIN_TOOL_COUNT);
    expect(stats.installed + stats.missing).toBe(stats.total);
  });

  test("category counts add up to the total", () => {
    const summed = Object.values(stats.byCategory).reduce((a, b) => a + b, 0);
    expect(summed).toBe(stats.total);
  });
});

/**
 * Lyrie Hack — Dependency Graph tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEPENDENCY_GRAPH_VERSION,
  extractDependencyGraph,
  languagesFromEcosystems,
} from "./dependency-graph";

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "lyrie-depgraph-"));

  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({
      name: "demo",
      dependencies: { express: "^4.17.1", lodash: "4.17.20" },
      devDependencies: { jest: "^29.0.0" },
    }),
  );

  writeFileSync(
    join(root, "requirements.txt"),
    "flask==2.0.0\n# comment\nrequests>=2.25.0\nnumpy\n",
  );

  writeFileSync(
    join(root, "go.mod"),
    `module example.com/demo

go 1.22

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/sys v0.20.0
)
`,
  );

  writeFileSync(
    join(root, "Cargo.toml"),
    `[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.36", features = ["full"] }

[dev-dependencies]
proptest = "1.4"
`,
  );

  writeFileSync(
    join(root, "Gemfile"),
    `source 'https://rubygems.org'
gem 'rails', '~> 7.0'
gem 'pg'
`,
  );

  writeFileSync(
    join(root, "composer.json"),
    JSON.stringify({
      name: "demo/demo",
      require: { "monolog/monolog": "^2.3" },
      "require-dev": { "phpunit/phpunit": "^10" },
    }),
  );

  // pom.xml
  writeFileSync(
    join(root, "pom.xml"),
    `<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
    </dependency>
  </dependencies>
</project>`,
  );

  // Nested manifest discovery
  mkdirSync(join(root, "frontend"));
  writeFileSync(
    join(root, "frontend", "package.json"),
    JSON.stringify({ name: "fe", dependencies: { react: "18.2.0" } }),
  );
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("extractDependencyGraph", () => {
  it("emits the Lyrie signature and version-shaped tag", () => {
    const g = extractDependencyGraph({ root });
    expect(g.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
    expect(DEPENDENCY_GRAPH_VERSION).toMatch(/^lyrie-/);
  });

  it("detects npm packages in package.json with scope", () => {
    const g = extractDependencyGraph({ root });
    const express = g.packages.find((p) => p.name === "express");
    expect(express).toBeDefined();
    expect(express!.ecosystem).toBe("npm");
    expect(express!.version).toBe("4.17.1");
    expect(express!.scope).toBe("direct");

    const jest = g.packages.find((p) => p.name === "jest");
    expect(jest).toBeDefined();
    expect(jest!.scope).toBe("dev");
  });

  it("parses requirements.txt with comparators", () => {
    const g = extractDependencyGraph({ root });
    const flask = g.packages.find((p) => p.name === "flask" && p.ecosystem === "pip");
    expect(flask).toBeDefined();
    expect(flask!.version).toBe("2.0.0");
    const numpy = g.packages.find((p) => p.name === "numpy" && p.ecosystem === "pip");
    expect(numpy).toBeDefined();
  });

  it("parses go.mod require blocks", () => {
    const g = extractDependencyGraph({ root });
    const gin = g.packages.find((p) => p.name === "github.com/gin-gonic/gin");
    expect(gin).toBeDefined();
    expect(gin!.version).toBe("v1.9.1");
    expect(gin!.ecosystem).toBe("go");
  });

  it("parses Cargo.toml for both string and table version syntax", () => {
    const g = extractDependencyGraph({ root });
    const serde = g.packages.find((p) => p.name === "serde" && p.ecosystem === "cargo");
    const tokio = g.packages.find((p) => p.name === "tokio" && p.ecosystem === "cargo");
    expect(serde).toBeDefined();
    expect(tokio).toBeDefined();
    expect(tokio!.version).toBe("1.36");
  });

  it("parses Gemfile gem statements", () => {
    const g = extractDependencyGraph({ root });
    const rails = g.packages.find((p) => p.name === "rails" && p.ecosystem === "ruby");
    expect(rails).toBeDefined();
    expect(rails!.version).toBe("7.0");
  });

  it("parses composer.json require + require-dev with scope", () => {
    const g = extractDependencyGraph({ root });
    const monolog = g.packages.find((p) => p.name === "monolog/monolog");
    expect(monolog).toBeDefined();
    expect(monolog!.scope).toBe("direct");
    const phpunit = g.packages.find((p) => p.name === "phpunit/phpunit");
    expect(phpunit!.scope).toBe("dev");
  });

  it("parses pom.xml dependencies as group:artifact", () => {
    const g = extractDependencyGraph({ root });
    const jackson = g.packages.find((p) => p.name === "com.fasterxml.jackson.core:jackson-databind");
    expect(jackson).toBeDefined();
    expect(jackson!.ecosystem).toBe("maven");
    expect(jackson!.version).toBe("2.13.0");
  });

  it("walks nested directories to depth N for manifests", () => {
    const g = extractDependencyGraph({ root });
    const react = g.packages.find((p) => p.name === "react");
    expect(react).toBeDefined();
    expect(react!.manifest).toBe("frontend/package.json");
  });

  it("populates the ecosystems list from observed manifests", () => {
    const g = extractDependencyGraph({ root });
    expect(g.ecosystems).toEqual(expect.arrayContaining(["npm", "pip", "go", "cargo", "ruby", "php", "maven"]));
  });

  it("languagesFromEcosystems maps to scanner-language ids", () => {
    const langs = languagesFromEcosystems(["npm", "pip", "go", "cargo"]);
    expect(langs).toEqual(expect.arrayContaining(["javascript", "typescript", "python", "go", "rust"]));
  });
});

/**
 * SarifViewer — framework-free web component for rendering SARIF scan results.
 *
 * Usage:
 *   import { SarifViewer } from "./SarifViewer";
 *   const viewer = new SarifViewer(container);
 *   viewer.load(sarifJson);
 */

import { parseSarif, groupByRule } from "./parse";
import type { SarifLog, FindingGroup, SarifLevel } from "./types";

const SEVERITY_COLORS: Record<SarifLevel, string> = {
  error: "#d73a4a",
  warning: "#e3a600",
  note: "#0075ca",
  none: "#6a737d",
};

const SEVERITY_ICONS: Record<SarifLevel, string> = {
  error: "✖",
  warning: "⚠",
  note: "ℹ",
  none: "·",
};

export class SarifViewer {
  private container: HTMLElement;
  private log: SarifLog | null = null;

  constructor(container: HTMLElement) {
    this.container = container;
  }

  /** Load a SARIF log from a JSON string or parsed object */
  load(input: string | object): void {
    this.log = parseSarif(input);
    this.render();
  }

  private render(): void {
    if (!this.log) return;
    this.container.innerHTML = "";

    for (const run of this.log.runs) {
      const runEl = document.createElement("section");
      runEl.className = "sarif-run";

      const header = document.createElement("h2");
      header.textContent = `${run.tool.driver.name}${
        run.tool.driver.version ? ` v${run.tool.driver.version}` : ""
      }`;
      runEl.appendChild(header);

      const groups = groupByRule(run);
      if (groups.length === 0) {
        const empty = document.createElement("p");
        empty.textContent = "No findings.";
        runEl.appendChild(empty);
      } else {
        for (const group of groups) {
          runEl.appendChild(this.renderGroup(group));
        }
      }

      this.container.appendChild(runEl);
    }
  }

  private renderGroup(group: FindingGroup): HTMLElement {
    const el = document.createElement("details");
    el.className = `sarif-group sarif-level-${group.level}`;
    el.open = group.level === "error";

    const summary = document.createElement("summary");
    const badge = document.createElement("span");
    badge.className = "sarif-badge";
    badge.style.color = SEVERITY_COLORS[group.level];
    badge.textContent = `${SEVERITY_ICONS[group.level]} ${group.level.toUpperCase()}`;

    const count = document.createElement("span");
    count.className = "sarif-count";
    count.textContent = ` (${group.results.length})`;

    const title = document.createElement("strong");
    title.textContent = ` ${group.ruleName}`;

    summary.appendChild(badge);
    summary.appendChild(title);
    summary.appendChild(count);

    if (group.ruleDescription) {
      const desc = document.createElement("span");
      desc.className = "sarif-desc";
      desc.textContent = ` — ${group.ruleDescription}`;
      summary.appendChild(desc);
    }

    if (group.helpUri) {
      const link = document.createElement("a");
      link.href = group.helpUri;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = " [docs]";
      link.className = "sarif-help-link";
      summary.appendChild(link);
    }

    el.appendChild(summary);

    const resultList = document.createElement("ul");
    resultList.className = "sarif-results";
    for (const result of group.results) {
      resultList.appendChild(this.renderResult(result));
    }
    el.appendChild(resultList);

    return el;
  }

  private renderResult(result: import("./types").SarifResult): HTMLElement {
    const li = document.createElement("li");
    li.className = "sarif-result";

    const loc = result.locations?.[0]?.physicalLocation;
    if (loc) {
      const uri = loc.artifactLocation?.uri ?? "";
      const line = loc.region?.startLine;
      const locSpan = document.createElement("code");
      locSpan.className = "sarif-location";
      locSpan.textContent = line ? `${uri}:${line}` : uri;
      li.appendChild(locSpan);
      li.appendChild(document.createTextNode(" — "));
    }

    const msg = document.createElement("span");
    msg.textContent = result.message.text;
    li.appendChild(msg);

    return li;
  }
}

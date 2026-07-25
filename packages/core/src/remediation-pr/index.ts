/**
 * @lyrie/core remediation-pr module \u2014 SARIF-driven auto-remediation PRs.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export { generateRemediationPr } from "./generate";
export type { GenerateRemediationPrOptions, GenerateRemediationPrResult } from "./generate";
export { generateHeaderFix } from "./header-fix";
export { generateDependencyFix } from "./dependency-fix";
export { openRemediationPr, realCommandRunner } from "./pr";
export type { CommandRunner, OpenPrOptions, OpenPrResult } from "./pr";
export type {
  MechanicalFinding,
  MissingHeaderFinding,
  DependencyFixFinding,
  MechanicalFindingKind,
  GeneratedDiff,
  MechanicalFixResult,
  MechanicalFixSkipped,
} from "./types";

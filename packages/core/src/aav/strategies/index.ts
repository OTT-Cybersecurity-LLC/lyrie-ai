/**
 * Lyrie AAV — Attack Strategies
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

export { CrescendoStrategy, buildCrescendoFromVector } from "./crescendo";
export type { CrescendoConfig, Message, AttackResult as CrescendoAttackResult } from "./crescendo";

export { TAPStrategy, generateAttackVariants, scoreBranch, makeTAPFromVector } from "./tap";
export type { TAPConfig, TAPBranch, AttackResult as TAPAttackResult } from "./tap";

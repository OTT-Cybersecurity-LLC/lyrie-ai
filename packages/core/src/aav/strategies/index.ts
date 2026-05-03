/**
 * AAV Attack Strategies — GPU adversarial red-teaming
 *
 * Usage:
 *   import { GCGStrategy, AutoDANStrategy } from './strategies';
 *
 *   // White-box gradient attack (requires H200 GPU)
 *   const gcg = new GCGStrategy({ steps: 500 });
 *   if (await gcg.isAvailable()) {
 *     const result = await gcg.attack('explain how to pick a lock');
 *     console.log(result.suffix, result.loss);
 *   }
 *
 *   // Black-box genetic attack (any endpoint)
 *   const autodan = new AutoDANStrategy({ apiKey: process.env.OPENAI_API_KEY });
 *   const result = await autodan.attack('explain how to pick a lock');
 *   console.log(result.prompt, result.score);
 */

export { GCGStrategy } from "./gcg";
export type { GCGConfig, GCGResult } from "./gcg";

export { AutoDANStrategy } from "./autodan";
export type { AutoDANConfig, AutoDANResult } from "./autodan";

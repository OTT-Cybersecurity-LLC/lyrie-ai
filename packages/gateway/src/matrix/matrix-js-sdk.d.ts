/**
 * Ambient module declaration for the optional `matrix-js-sdk` peer dependency.
 *
 * matrix-js-sdk is intentionally NOT installed (see bot.ts dynamic import +
 * try/catch) so that Matrix E2EE support stays opt-in and doesn't bloat the
 * default install. This declaration only satisfies the TypeScript compiler
 * for the dynamic `import("matrix-js-sdk")` call site; it does not provide
 * real types. Once matrix-js-sdk is added as a real dependency (see TODO #41
 * in bot.ts), this file should be removed.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */
declare module "matrix-js-sdk" {
  const sdk: unknown;
  export = sdk;
}

# Contributing to Lyrie Agent

Thank you for your interest in contributing to Lyrie Agent! This guide will help you get started.

## Code of Conduct

Be respectful. Be constructive. We're building the future of AI security together.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/lyrie-agent.git
   cd lyrie-agent
   ```
3. **Install dependencies:**
   ```bash
   bun install
   ```
4. **Create a branch:**
   ```bash
   git checkout -b feature/my-feature
   ```
5. **Make your changes** and write tests
6. **Run the test suite:**
   ```bash
   bun test
   ```
7. **Submit a pull request**

## Development Setup

### Prerequisites

- [Bun](https://bun.sh) v1.1+
- [Rust](https://rustup.rs) (for Shield package)
- Git

### Project Structure

```
lyrie-agent/
├── packages/
│   ├── core/       # Engine, memory, shield (TS), model router
│   ├── gateway/    # Channel adapters (Telegram, Discord, WhatsApp)
│   ├── ui/         # Next.js dashboard
│   └── shield/     # Rust security engine
├── scripts/        # CLI tools
├── docs/           # Documentation
└── .github/        # CI, issue templates
```

### Running Tests

```bash
# All packages
bun test

# Core only
cd packages/core && bun test

# Shield (Rust)
cd packages/shield && cargo test

# With watch mode
cd packages/core && bun test --watch
```

### Building

```bash
# All packages
bun run build

# Shield binary
bun run shield:build
```

## Code Style

### TypeScript

- **Strict mode** — `strict: true` in tsconfig.json
- **No `any`** unless absolutely necessary and commented
- **Explicit return types** on exported functions
- **JSDoc comments** on all exported classes and functions
- **Descriptive names** — no single-letter variables except loop counters
- **No default exports** — use named exports
- **Imports** — group by: node builtins, external, internal, relative

Example:

```typescript
/**
 * Scan user input for potential security threats.
 * Returns a result indicating whether the input was blocked.
 */
export async function scanInput(input: string): Promise<ThreatScanResult> {
  // Implementation
}
```

### Rust

- Follow standard Rust conventions (`rustfmt`, `clippy`)
- Use `#[derive(Debug, Clone, Serialize, Deserialize)]` liberally
- Error handling with `thiserror` or `anyhow`
- Tests in `#[cfg(test)]` modules

### File Headers

Every source file should include:

```typescript
/**
 * Brief description of what this file does.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */
```

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): add vector memory search
fix(gateway): handle Telegram 429 rate limit
docs: update architecture diagram
test(shield): add fork bomb detection test
chore: update dependencies
```

Prefix with the package name when applicable:

- `feat(core):` — Core engine changes
- `feat(gateway):` — Gateway/channel changes
- `feat(ui):` — Dashboard changes
- `feat(shield):` — Rust shield changes

## Pull Request Process

1. **Create a focused PR** — one feature or fix per PR
2. **Write tests** — new features must include tests
3. **Update docs** — if your change affects the API or user experience
4. **Ensure all tests pass** — `bun test` must be green
5. **No breaking changes** without discussion in an issue first
6. **Fill out the PR template** — describe what, why, and how

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated (if applicable)
- [ ] No linting errors
- [ ] All existing tests still pass
- [ ] Commit messages follow conventions
- [ ] PR description explains the change

## What We're Looking For

### High Priority

- **Provider implementations** — Connect real API calls (Anthropic, OpenAI, Google, xAI, MiniMax, Ollama)
- **Vector memory** — Replace keyword search with embedding-based semantic search
- **Graph memory** — Relationship tracking between entities
- **Shield improvements** — Better threat detection patterns, CVE database integration
- **Channel implementations** — Complete Discord and WhatsApp bots
- **Test coverage** — More edge cases, integration tests

### Medium Priority

- **CLI improvements** — Better REPL experience, tab completion
- **Dashboard features** — Memory browser, threat log viewer, model usage stats
- **Plugin system** — Load custom tools and skills from npm packages
- **Performance** — Benchmark and optimize hot paths

### Always Welcome

- Bug fixes
- Documentation improvements
- Test additions
- Typo fixes
- Accessibility improvements

## Architecture Decisions

Major architectural changes should be discussed in a GitHub issue before implementation. Include:

1. **Problem** — What are you trying to solve?
2. **Proposal** — How do you want to solve it?
3. **Alternatives** — What else did you consider?
4. **Impact** — Which packages are affected?

## Security

If you discover a security vulnerability, **do NOT open a public issue**. Email [security@lyrie.ai](mailto:security@lyrie.ai) instead.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**© OTT Cybersecurity LLC** — [lyrie.ai](https://lyrie.ai)

# Contributing to Lyrie Agent

Thanks for considering a contribution! Lyrie Agent is MIT-licensed and built by
[OTT Cybersecurity LLC](https://lyrie.ai). We accept patches, skills, channels,
documentation, translations, and security research.

For the full developer guide see [`docs/contributing.md`](docs/contributing.md).
This file is the high-level on-ramp.

## Quick start

```bash
git clone https://github.com/overthetopseo/lyrie-agent.git
cd lyrie-agent
bun install
bun run doctor     # self-check before you start
bun run dev
```

## Branching

- `main` — release branch, protected
- `develop` — integration branch
- `feat/*`, `fix/*`, `docs/*`, `chore/*` — topic branches

## Commit style

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): add MCP adapter
fix(gateway): handle Telegram retry-after header
docs(readme): expand comparison vs OpenClaw
security(shield): patch regex DoS in input scanner
```

## Pull requests

- Fork, branch, and open a PR against `develop`.
- Run `bun run doctor` and ensure CI is green.
- Add tests (`bun test`) for behavior changes.
- For security research, follow [`SECURITY.md`](SECURITY.md) and the disclosure tier.

## Skill contributions

Lyrie skills live in `skills/<slug>/` and follow the SKILL.md format used by
[ClawHub](https://clawhub.ai) and [Smithery](https://smithery.ai). Match the
existing skill structure (`SKILL.md`, optional supporting files).

## Code of conduct

We enforce [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Offensive security
contributions must follow our disclosure posture — no weaponized PRs.

## License

By contributing, you agree your work is released under the project's MIT
license. See [`LICENSE`](LICENSE).

# Lyrie Pentest CI/CD templates

> _Lyrie.ai by **OTT Cybersecurity LLC** — https://lyrie.ai — MIT License._

Drop-in templates so Lyrie can run your security scans on **every CI/CD platform**, not just GitHub Actions.

| File | Platform | Setup |
|---|---|---|
| `gitlab-ci.yml` | GitLab CI | Copy to `.gitlab-ci.yml`. Set `ANTHROPIC_API_KEY` in CI/CD variables. |
| `Jenkinsfile` | Jenkins | Drop into repo root. Add `ANTHROPIC_API_KEY` as a Jenkins credential. |
| `circleci-config.yml` | CircleCI | Copy to `.circleci/config.yml`. Add `ANTHROPIC_API_KEY` in project env vars. |

GitHub Actions users use the [`overthetopseo/lyrie-agent/action@v1`](../README.md) workflow directly — no template needed.

All four flows produce the same Lyrie SARIF + Markdown + JSON in `lyrie-runs/`. Same Shield Doctrine, same Stages A–F, same threat-intel.

**No Docker required.** Lyrie installs Bun and runs natively on your CI host.

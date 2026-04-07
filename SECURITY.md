# Security Policy

## Our Philosophy

Security is not a feature of Lyrie — it IS Lyrie.

While other agent platforms have accumulated hundreds of CVEs, we built security into every layer from day one.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

- Email: security@lyrie.ai
- Do NOT open a public GitHub issue for security vulnerabilities
- We will acknowledge receipt within 24 hours
- We aim to provide a fix within 72 hours for critical issues

## Security Architecture

### Layer 1: The Shield
- All agent actions are sandboxed by default
- File system access is scoped to workspace directories
- Network access requires explicit allowlisting
- Shell commands go through security classification

### Layer 2: Memory Protection
- Memory is encrypted at rest
- Cross-agent memory isolation
- No credential leakage between sessions
- Versioned memory with tamper detection

### Layer 3: Channel Security
- End-to-end encryption where supported
- Token rotation and secure storage
- Rate limiting on all endpoints
- Authentication required for all API access

### Layer 4: Code Integrity
- Codebase under 30,000 lines (fully auditable)
- All dependencies pinned and audited
- No eval() or dynamic code execution without sandboxing
- Regular automated security scanning

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |
| < 1.0   | ❌        |

## Bug Bounty

We plan to launch a bug bounty program after v1.0 release.

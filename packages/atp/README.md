# Agent Trust Protocol (ATP) v1.0

```
Internet Engineering Task Force                            G. Sheetrit, Ed.
Independent Submission                                              Lyrie
Intended status: Standards Track                                  May 2026
Expires: November 2026
```

## Abstract

The Agent Trust Protocol (ATP) defines a cryptographic standard for AI
agent identity, authorisation scope, action attribution, and runtime
state attestation. ATP gives operators, auditors, and peer systems the
ability to answer four questions about any AI agent action with
cryptographic certainty: **who took it**, **were they authorised**,
**what exactly did they do**, and **has the agent itself been tampered
with since deployment**.

ATP is to AI agents what TLS is to web sessions and what x.509 is to web
servers: a small, mandatory, deterministic substrate that every higher
layer of the AI ecosystem can build trust on. This document describes
ATP version 1.0 as a complete wire-format specification suitable for
multiple independent implementations.

## Status of This Memo

This document is a working draft. It is intended to be submitted to the
Internet Engineering Task Force (IETF) for consideration as a Standards
Track RFC. Distribution is unlimited.

The reference implementation accompanying this specification is
`@lyrie/atp` (TypeScript, MIT-licensed, Ed25519 via Node built-ins). It
is interoperable with any conformant implementation.

Comments are solicited and should be addressed to the Lyrie engineering
list (`dev@lyrie.ai`) or filed against the public issue tracker.

## Copyright Notice

Copyright (c) 2026 OTT Cybersecurity LLC. All rights reserved.

This document is subject to the BSD-style license described in the
LICENSE file of the repository accompanying this specification.

---

## 1. Introduction

### 1.1 Motivation

Throughout 2025–2026, autonomous AI agents transitioned from research
artifacts to production infrastructure. With that shift came a class of
incidents — MCP RCE family (CVE-2026-30615 et al.), unbounded sub-agent
privilege escalation, prompt-injection hijacks, and silent tool-poisoning
attacks — that revealed a structural absence: **AI agents had no
cryptographic identity, no authenticated scope, and no attributable
action log**.

Existing standards do not fill this gap.

* TLS authenticates **services**, not agents.
* JWT authenticates **users**, not the AI acting on their behalf.
* x.509 authenticates **machines**, not the model running on them.
* OAuth scopes apply to **API clients**, not to autonomous reasoners
  whose tool list is dynamic.

ATP fills the gap. It provides:

* **Agent Identity Certificates (AICs)** — self-signed Ed25519 passports
  that bind one agent instance to one model, one system prompt, one
  scope, and one operator.
* **Action Receipts** — tamper-evident records that an agent took an
  action under a specific AIC, optionally counter-signed by the receiver.
* **Scope Declaration Language (SDL)** — a JSON dialect describing what
  an agent may do, with composition rules that prevent privilege
  escalation between parent and sub-agent.
* **Trust Chains** — verifiable lineage from a root operator-issued AIC
  down to any sub-agent, with the cryptographically enforced invariant
  that scope only narrows.
* **Breach Attestations** — periodic signed snapshots of agent state
  that detect post-deployment tampering of system prompt, memory, or
  tool history.

### 1.2 Design Goals

1. **Determinism.** Every artifact has exactly one canonical encoding;
   two correct implementations must produce byte-identical signed forms.
2. **Cross-language portability.** No PEM, no ASN.1 in the wire format,
   no language-specific JSON quirks. JSON + base64-standard encoding +
   Ed25519 raw 32-byte keys.
3. **Zero external dependencies in the reference implementation.**
   Implementable on any platform with SHA-256 + Ed25519 + JSON.
4. **Composability.** Every primitive is independently verifiable and
   the cross-primitive verifier is a thin dispatcher, not a god-object.
5. **Forward compatibility.** Verification error codes are stable; new
   codes are non-breaking; new fields are required to be ignored by
   implementations that do not understand them.

### 1.3 Non-Goals

ATP intentionally does not specify:

* **Key storage.** Operators store private keys however they wish (HSM,
  KMS, file). ATP is key-storage-agnostic.
* **Revocation distribution.** This document defines a revocation
  *interface* (`isRevoked: CertId → boolean`) but not a revocation
  protocol. CRL and OCSP-style mechanisms may be specified in a
  companion document.
* **Memory canonicalisation.** Breach Attestations consume hex SHA-256
  digests of memory and tool-call history; the inputs producing those
  digests are application-defined.
* **Model authenticity.** A `modelHash` field exists for local/open-weight
  deployments, but ATP does not specify how to obtain or verify it.

---

## 2. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL
NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and
**OPTIONAL** in this document are to be interpreted as described in
RFC 2119.

* **Agent.** A software entity executing autonomous reasoning, typically
  driven by a large language model, that may invoke tools, spawn
  sub-agents, or take consequential external actions.
* **Operator.** A human or organisational principal accountable for an
  agent's actions. Identified by `operatorId` in an AIC.
* **AIC.** Agent Identity Certificate. The Ed25519 self-signed
  passport described in §3.1.
* **CertId.** The lower-case hex SHA-256 of the canonical signed form
  of an AIC.
* **SDL.** Scope Declaration Language. The JSON-encoded authorisation
  policy embedded in every AIC.
* **Trust Chain.** An ordered list of AICs `[root, ..., leaf]` in which
  each child is bound to its parent and operates within a subset of the
  parent's scope.
* **Receipt.** Action Receipt. A signed record of one agent action.
* **Attestation.** Breach Attestation. A signed snapshot of agent
  runtime state.

---

## 3. Protocol Primitives

This section is normative. All five primitives are JSON objects with the
field `version` set to the string `"1.0"` for this specification.

Canonical JSON encoding (§3.0) MUST be used wherever a SHA-256 digest or
Ed25519 signature is computed over a structured payload.

### 3.0 Canonical JSON Encoding

Implementations MUST produce a single canonical byte sequence per
artifact when computing CertIds, signatures, and attestation hashes.
The canonicalisation algorithm is a strict subset of RFC 8785 (JSON
Canonicalization Scheme):

1. Object keys are sorted lexicographically (UTF-16 code-unit order).
2. No insignificant whitespace is emitted.
3. Fields whose value is `undefined` (or missing) MUST NOT appear.
4. `NaN`, `Infinity`, `-Infinity`, `BigInt`, function, and symbol values
   MUST be rejected.
5. ATP timestamps are integers (Unix milliseconds). Implementations MUST
   reject floating-point timestamps; this guarantees deterministic
   number serialisation independent of the host's float-formatting.

### 3.1 Agent Identity Certificate (AIC)

```jsonc
{
  "version": "1.0",
  "agentId": "uuid-v4",
  "modelId": "anthropic/claude-sonnet-4-6",
  "modelHash": "sha256-hex-of-weights-or-omitted",
  "systemPromptHash": "sha256-hex-of-system-prompt",
  "scope": { /* ScopeDeclaration, see §3.3 */ },
  "operatorId": "guy@lyrie.ai",
  "issuedAt": 1714704000000,
  "expiresAt": 1714790400000,
  "publicKey":  "<base64-standard 32 bytes>",
  "signature":  "<base64-standard 64 bytes>",
  "parentCertId": "sha256-hex-of-parent-or-omitted"
}
```

The `signature` field covers the canonical JSON of every other field
(itself excluded). Verification MUST fail if any field has been mutated
after signing.

The `publicKey` and `privateKey` are raw Ed25519 keys, base64-standard
encoded (32 raw bytes → 44 base64 characters; 64-byte signatures → 88
characters). PEM encoding is **NOT** used in the wire format.

The `CertId` of an AIC is the lower-case hex SHA-256 of its canonical
signed form. Two equivalent AICs MUST yield equal CertIds.

#### 3.1.1 Validity

An AIC is valid at time `t` (Unix ms) if and only if:

* `cert.signature` verifies against `cert.publicKey` over the canonical
  unsigned form, AND
* `cert.issuedAt ≤ t ≤ cert.expiresAt`, AND
* the embedded scope structurally validates (§3.3.2), AND
* the implementation's revocation oracle returns `false` for `CertId`.

#### 3.1.2 Operator Linkage

The `operatorId` field is an opaque string that names a human or
organisational principal accountable for the agent. It MUST be present.
ATP does not require operators to also hold ATP keys; in deployments
where they do, the operator identity may be cryptographically anchored
through a companion specification.

### 3.2 Action Receipt

```jsonc
{
  "version": "1.0",
  "receiptId": "uuid-v4",
  "agentCertId": "sha256-hex of issuing AIC",
  "action": {
    "tool":       "send_email",
    "params":     { "to_hash": "sha256:...", "subject": "..." },
    "timestamp":  1714704001000
  },
  "result": {
    "success":    true,
    "summary":    "Sent (non-sensitive description)",
    "timestamp":  1714704001500
  },
  "agentSignature":     "<base64-standard 64 bytes>",
  "receiverSignature":  "<base64-standard 64 bytes; OPTIONAL>",
  "receiverPublicKey":  "<base64-standard 32 bytes; required if receiverSignature present>"
}
```

The agent signs the canonical JSON of `{ version, receiptId, agentCertId,
action, result }`. The receiver, if present, signs the **same** canonical
payload — so the agent and receiver signatures are independent and may
be added in either order without invalidating each other.

`action.params` MUST NOT contain plaintext secrets. Implementations
SHOULD substitute `{ "to_hash": "sha256:..." }` for sensitive fields.

`result.summary` MUST be safe to publish in audit logs. Implementations
SHOULD strip personally identifiable or operationally sensitive content.

### 3.3 Scope Declaration Language (SDL)

```jsonc
{
  "version": "1.0",
  "allowedTools":       ["read_file", "send_email"],
  "deniedTools":        ["shell_exec"],
  "allowedDomains":     ["*.x.com", "lyrie.ai"],
  "maxSubAgentDepth":   1,
  "requireApprovalFor": ["send_email"],
  "temporalScope": {
    "validFrom":    1714704000000,
    "validUntil":   1714790400000,
    "allowedHours": [9,10,11,12,13,14,15,16,17]
  },
  "dataScope": {
    "allowedLabels": ["public", "internal"],
    "deniedLabels":  ["secret", "pii"]
  }
}
```

#### 3.3.1 Subset Rule (Normative)

A scope `child` is a **subset** of `parent` if and only if all of:

1. For every `t ∈ child.allowedTools`:
   `t ∉ parent.deniedTools` AND (`t ∈ parent.allowedTools` OR
   `"*" ∈ parent.allowedTools`).
2. `child.deniedTools ⊇ parent.deniedTools`.
3. If `parent.allowedDomains` is set, `child.allowedDomains` MUST be set
   and every entry MUST be covered by a parent entry under the glob
   semantics of §3.3.3.
4. `child.maxSubAgentDepth ≤ parent.maxSubAgentDepth`.
5. `child.requireApprovalFor ⊇ parent.requireApprovalFor`.
6. The temporal window of `child` is contained in that of `parent`.
7. `child.dataScope.allowedLabels ⊆ parent.dataScope.allowedLabels`.
8. `child.dataScope.deniedLabels ⊇ parent.dataScope.deniedLabels`.

This rule is the cryptographic primitive that prevents sub-agent
privilege escalation: a Trust Chain whose any hop violates it MUST be
rejected by every conformant verifier.

#### 3.3.2 Validation

`maxSubAgentDepth` MUST be a non-negative integer. `temporalScope.allowedHours`
entries MUST be integers in 0–23. `temporalScope.validFrom ≤ validUntil`
when both are present. All array fields MUST contain only strings.

#### 3.3.3 Domain Glob Semantics

Domain patterns MAY be exact (`api.x.com`), single-wildcard subdomain
(`*.x.com` matches `a.x.com` and `a.b.x.com` but NOT `x.com`), or
universal (`*` matches anything). No other glob constructs are permitted
in v1.0.

### 3.4 Trust Chain Rules

A Trust Chain is the wire structure:

```jsonc
{
  "rootCertId": "sha256-hex of chain[0]",
  "chain": [ /* AIC, AIC, ..., AIC */ ],
  "depth": 2
}
```

A Trust Chain `C` is valid if and only if:

1. `|C.chain| ≥ 1` and `|C.chain| - 1 == C.depth`.
2. `CertId(C.chain[0]) == C.rootCertId`.
3. `C.chain[0].parentCertId` is absent (the root MUST NOT chain upward).
4. For every `i > 0`:
   * `C.chain[i].parentCertId == CertId(C.chain[i-1])`,
   * Each AIC individually verifies (§3.1.1) under the same temporal
     evaluation point,
   * `C.chain[i].scope` is a subset of `C.chain[i-1].scope` (§3.3.1),
   * `C.chain[i-1].issuedAt ≤ C.chain[i].issuedAt ≤ C.chain[i-1].expiresAt`,
   * `C.chain[i-1].scope.maxSubAgentDepth ≥ |C.chain| - i`.

### 3.5 Breach Attestation

```jsonc
{
  "version": "1.0",
  "agentId": "uuid-v4",
  "attestedAt": 1714704005000,
  "stateHash": "sha256-hex(canonical({systemPromptHash, memoryHash, toolCallHistoryHash}))",
  "previousHash": "sha256-hex of previous attestation (canonical signed form)",
  "signature":   "<base64-standard 64 bytes>",
  "attestorId":         "lyrie-verification-service",
  "attestorSignature":  "<base64-standard 64 bytes; OPTIONAL>",
  "attestorPublicKey":  "<base64-standard 32 bytes; required if attestorSignature present>"
}
```

#### 3.5.1 State Hash

`stateHash` is computed over the canonical JSON of the object
`{ systemPromptHash, memoryHash, toolCallHistoryHash }`. The three
inputs are themselves SHA-256 hex digests over application-defined
canonical encodings of:

* the agent's system prompt at attestation time,
* the agent's memory store at attestation time,
* the agent's complete ordered tool-call history.

#### 3.5.2 Drift Detection

A verifier given an `expectedStateHash` (derived independently from the
verifier's view of the agent's state) MUST compare it against
`attestation.stateHash`. Inequality indicates drift — either the
attestation is stale, or the agent's state has been tampered with after
the attestation was issued. Verifiers MUST surface this as the stable
error code `ATP_ATTESTATION_DRIFT`.

#### 3.5.3 Attestation Chains

Successive attestations MAY form a hash chain via `previousHash`. When
they do, every conformant chain verifier MUST reject:

* a chain whose hop's `previousHash` does not equal
  `sha256-hex(canonical(prev_attestation))`,
* a chain whose `attestedAt` is not monotonically non-decreasing.

---

## 4. Security Considerations

### 4.1 Threat Model

ATP defends against:

1. **Forged agent identity.** Without the AIC's private key, an attacker
   cannot present a valid AIC for an agent they do not control.
2. **Action repudiation.** A signed receipt is non-repudiable evidence
   that the holder of the AIC's private key took the recorded action.
3. **Sub-agent privilege escalation.** The Trust Chain subset rule
   cryptographically prevents a child from claiming authority its
   parent never held — the rule that, applied retrospectively, would
   have prevented the MCP RCE family of 2026.
4. **Post-deployment tampering of agent state.** Periodic Breach
   Attestations whose state hash diverges from a verifier's
   independently computed view detect prompt-injection persistence,
   memory poisoning, and tool-history rewriting.

### 4.2 Out of Scope

ATP does **not** defend against:

* **Compromise of the AIC private key.** This is equivalent to
  compromise of the agent itself; revocation is the only remedy.
* **Coerced legitimate actions.** A correctly-signed receipt for an
  attacker-induced action is, by ATP's definitions, a valid receipt —
  detection of such cases is upstream of ATP.
* **Side-channel attribution.** ATP signs the action payload as
  declared; if the agent's reasoning was hijacked by a prompt-injection
  attack into producing that payload, ATP records the result faithfully
  but does not by itself flag the cause.

### 4.3 Cryptographic Choices

Ed25519 is mandatory in v1.0. SHA-256 is mandatory for all hash inputs.
A future ATP v1.1 MAY add post-quantum algorithms; v1.0 verifiers MUST
reject artifacts using algorithms not specified here.

### 4.4 Receipt Privacy

`action.params` and `result.summary` MUST NOT carry plaintext secrets.
Implementations are encouraged to substitute hashes or redacted
descriptors. ATP does not encrypt receipts; if confidentiality of the
audit log is required, transport-level encryption SHOULD be applied
externally.

### 4.5 Clock Skew

All timestamp comparisons SHOULD apply implementation-configured skew
tolerances. The reference implementation uses zero by default; deployers
operating across federated trust boundaries SHOULD permit ±60 seconds.

### 4.6 Replay Resistance

Action Receipts include a `receiptId` (UUID v4) and timestamps. Ledger
operators SHOULD detect replays by indexing on `(agentCertId, receiptId)`.

---

## 5. IANA Considerations

This document requests IANA registration of the following items in a
future "ATP Parameters" registry:

* The protocol version string `"1.0"`.
* The set of `VerificationErrorCode` values defined in §6 of the
  reference implementation, including but not limited to:
  `ATP_VERSION_MISMATCH`, `ATP_SIGNATURE_INVALID`,
  `ATP_PUBLIC_KEY_INVALID`, `ATP_CERT_EXPIRED`,
  `ATP_CERT_NOT_YET_VALID`, `ATP_CERT_REVOKED`, `ATP_SCOPE_INVALID`,
  `ATP_SCOPE_WIDENING`, `ATP_CHAIN_BROKEN`,
  `ATP_CHAIN_DEPTH_EXCEEDED`, `ATP_RECEIPT_AGENT_MISMATCH`,
  `ATP_ATTESTATION_DRIFT`, `ATP_ATTESTATION_CHAIN_BROKEN`,
  `ATP_TEMPORAL_OUT_OF_WINDOW`, `ATP_TOOL_NOT_ALLOWED`,
  `ATP_DOMAIN_NOT_ALLOWED`, `ATP_MALFORMED`.

A media type `application/atp+json` MAY be registered for ATP artifact
exchange. This is not specified normatively in v1.0.

---

## 6. References

### 6.1 Normative References

* RFC 2119 — Key words for use in RFCs.
* RFC 4648 — The Base16, Base32, and Base64 Data Encodings.
* RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
* RFC 8785 — JSON Canonicalization Scheme (JCS). The ATP canonical
  encoding is a strict subset.
* FIPS 180-4 — Secure Hash Standard (SHA-256).

### 6.2 Informative References

* OWASP — *Top 10 for LLM Applications, 2025/2026*.
* Microsoft — *Agent Governance Toolkit, April 2026*.
* CVE-2026-30615 — MCP RCE family (sub-agent privilege escalation).
* Lyrie — *v1.0 Specification* and *Competitive Teardown* (Lyrie
  Engineering, 2026).

---

## Appendix A: Worked Example

A root operator-issued AIC, a sub-agent AIC, an Action Receipt, and a
Breach Attestation follow. The example uses the reference implementation
(`@lyrie/atp`) but every value is verifiable by any conformant
implementation.

```typescript
import {
  issueAic, signReceipt, attestState,
  buildTrustChain, verifyTrustChain,
  makeScope, sha256Hex,
} from "@lyrie/atp";

// 1. Operator issues a wide-scope root AIC.
const rootScope = makeScope({
  allowedTools: ["read_file", "send_email", "spawn_subagent"],
  maxSubAgentDepth: 1,
  requireApprovalFor: ["send_email"],
});
const root = issueAic({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("You are an autonomous research agent."),
  scope: rootScope,
  operatorId: "guy@lyrie.ai",
});

// 2. The root spawns a narrowed sub-agent.
const childScope = makeScope({
  allowedTools: ["read_file"],         // strictly narrower
  maxSubAgentDepth: 0,
  requireApprovalFor: ["send_email"],  // inherits parent's approvals
});
const child = issueAic({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("You are a read-only research worker."),
  scope: childScope,
  operatorId: "guy@lyrie.ai",
  parentCertId: root.certId,
});

// 3. Build and verify the chain.
const chain = buildTrustChain([root.cert, child.cert]);
const result = verifyTrustChain(chain);  // { valid: true }

// 4. The child performs an action and signs a receipt.
const receipt = signReceipt({
  cert: child.cert,
  privateKey: child.keyPair.privateKey,
  action: {
    tool: "read_file",
    params: { path: "/research/notes.md" },
    timestamp: Date.now(),
  },
  result: {
    success: true,
    summary: "read 4096 bytes",
    timestamp: Date.now(),
  },
});

// 5. The child attests state for tamper detection.
const attestation = attestState({
  cert: child.cert,
  privateKey: child.keyPair.privateKey,
  state: {
    systemPromptHash: child.cert.systemPromptHash,
    memoryHash: sha256Hex("(memory snapshot bytes)"),
    toolCallHistoryHash: sha256Hex("(tool history bytes)"),
  },
});
```

If, in step 2, `childScope` had set `allowedTools: ["read_file", "shell_exec"]`,
the call to `verifyTrustChain` in step 3 would return
`{ valid: false, code: "ATP_SCOPE_WIDENING" }` — the cryptographic rule
that prevents sub-agent privilege escalation.

## Appendix B: Compliance Levels

ATP defines three compliance levels for use by implementers and auditors.

| Level         | AIC | Receipts | SDL + Trust Chain | Breach Attestation |
|---------------|:---:|:--------:|:-----------------:|:------------------:|
| ATP-Basic     | ✓   | ✓        |                   |                    |
| ATP-Standard  | ✓   | ✓        | ✓                 |                    |
| ATP-Full      | ✓   | ✓        | ✓                 | ✓                  |

Implementations MUST advertise their highest supported level. The
reference implementation supports ATP-Full.

The ATP Compliance Badge (`generateBadge`) emits a verifiable JSON
payload alongside the SVG that contains the agent's AIC and most-recent
attestation, allowing any consumer to re-verify the badge claims with
the standard verifier.

---

*Author: Lyrie Engineering · OTT Cybersecurity LLC · `dev@lyrie.ai` · `https://lyrie.ai`*

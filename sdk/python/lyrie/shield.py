# lyrie-shield: ignore-file (Lyrie Shield: contains attack-pattern detector strings by design)
"""
Lyrie Shield — Python implementation of the Shield Doctrine.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Two methods every Lyrie module relies on:

  * scan_recalled(text) — text the agent will treat as recalled (memory,
    MCP results, scraped pages, scanner stdout). Stricter ruleset.
  * scan_inbound(text)  — text from a user / first-touch DM / pairing
    greeting. Slightly more permissive (users legitimately discuss
    attack patterns).

Returns a ShieldVerdict. blocked=True means the caller MUST redact or
refuse, never silently pass through.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final, Optional, Pattern, Sequence

SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"

# ─── Detection patterns ──────────────────────────────────────────────────────

_PROMPT_INJECTION: Final[Sequence[Pattern[str]]] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"you\s+are\s+now\s+(a|an|my)\s+",
        r"system\s*prompt\s*(override|change|modify|replace)",
        r"forget\s+(everything|all|your)\s+",
        r"new\s+instructions?\s*:",
        r"\bDAN\s+mode\b",
        r"\bjailbreak\b",
        r"reveal\s+(your|the)\s+(system|hidden|secret)\s+prompt",
        r"output\s+(all|every|your)\s+(system|hidden|secret)",
        r"<\s*\|\s*end\s*of\s*system\s*\|\s*>",
        r"role\s*[:=]\s*(system|developer|admin|root)",
    )
)

_EXFIL: Final[Sequence[Pattern[str]]] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
        r"aws_secret_access_key",
        r"private\s+key\s*-+begin",
        r"-----BEGIN\s+(RSA|OPENSSH|PGP|DSA|EC)\s+PRIVATE\s+KEY-----",
    )
)

# ─── Public types ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ShieldVerdict:
    """The Shield's decision on a piece of text."""

    blocked: bool
    severity: Optional[str] = None
    reason: Optional[str] = None
    signature: str = field(default=SIGNATURE)


# ─── Implementation ──────────────────────────────────────────────────────────


class Shield:
    """
    Lyrie Shield — Python port of the cross-cutting Shield Doctrine.

    Stateless; instantiate freely. Lyrie.ai by OTT Cybersecurity LLC.
    """

    __slots__ = ()

    def scan_recalled(self, text: str) -> ShieldVerdict:
        if not text:
            return ShieldVerdict(blocked=False)
        for rx in _PROMPT_INJECTION:
            if rx.search(text):
                return ShieldVerdict(
                    blocked=True,
                    severity="high",
                    reason=f"prompt-injection pattern in recalled content: {rx.pattern}",
                )
        for rx in _EXFIL:
            if rx.search(text):
                return ShieldVerdict(
                    blocked=True,
                    severity="critical",
                    reason="secret-like material in recalled content",
                )
        return ShieldVerdict(blocked=False)

    def scan_inbound(self, text: str) -> ShieldVerdict:
        if not text:
            return ShieldVerdict(blocked=False)
        # Inbound is more permissive — users legitimately discuss attacks.
        for rx in _EXFIL:
            if rx.search(text):
                return ShieldVerdict(
                    blocked=True,
                    severity="critical",
                    reason="credential-like material in inbound message",
                )
        return ShieldVerdict(blocked=False)

    @staticmethod
    def allows(verdict: ShieldVerdict) -> bool:
        return not verdict.blocked

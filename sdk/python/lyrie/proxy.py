# lyrie-shield: ignore-file (Lyrie HTTP Proxy: contains credential-shape detector strings by design)
"""
Lyrie HTTP Proxy — Python port (capture + classify + signal detection).

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Replay + mutator support is intentionally minimal here; the full
mutator surface lives in the TypeScript implementation. The Python SDK
focuses on programmatic capture + signal detection so security teams
can drop it into Python pentest pipelines.
"""

from __future__ import annotations

import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final, Literal, Optional

from lyrie.shield import Shield

PROXY_VERSION: Final[str] = "lyrie-http-proxy-py-1.0.0"
SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
SignalKind = Literal[
    "missing-security-header", "weak-cookie-flag", "open-cors",
    "auth-token-in-url", "verbose-error", "secret-in-response",
    "graphql-introspection-enabled",
]
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(slots=True)
class HttpRequest:
    id: str
    method: HttpMethod
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    captured_at: str = ""
    surface: Optional[str] = None


@dataclass(slots=True)
class HttpResponse:
    id: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    duration_ms: int = 0
    received_at: str = ""
    shielded: bool = False
    shield_reason: Optional[str] = None


@dataclass(slots=True)
class HttpSignal:
    kind: SignalKind
    severity: Severity
    description: str
    evidence: Optional[str] = None


@dataclass(slots=True)
class HttpExchange:
    request: HttpRequest
    response: Optional[HttpResponse] = None
    signals: list[HttpSignal] = field(default_factory=list)


@dataclass(slots=True)
class Mutator:
    kind: Literal[
        "header-add", "header-set", "header-remove",
        "param-set", "body-replace", "method-swap",
    ]
    target: Optional[str] = None
    value: Optional[str] = None


# ─── HttpProxy ───────────────────────────────────────────────────────────────


class HttpProxy:
    """
    Lyrie HTTP Proxy.

    Captures requests in memory, classifies, and runs 7 signal detectors.
    Lyrie.ai by OTT Cybersecurity LLC.
    """

    __slots__ = ("_max_body", "_max_exchanges", "_shield_responses", "_deny",
                 "_allow", "_shield", "_exchanges")

    def __init__(
        self,
        *,
        max_body_bytes: int = 200_000,
        max_exchanges: int = 1_000,
        shield_responses: bool = True,
        deny_hosts: Optional[list[str]] = None,
        allow_hosts: Optional[list[str]] = None,
        shield: Optional[Shield] = None,
    ) -> None:
        self._max_body = max_body_bytes
        self._max_exchanges = max_exchanges
        self._shield_responses = shield_responses
        self._deny = {h.lower() for h in (deny_hosts or [])}
        self._allow = {h.lower() for h in allow_hosts} if allow_hosts else None
        self._shield = shield or Shield()
        self._exchanges: list[HttpExchange] = []

    def send(
        self,
        method: HttpMethod,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        timeout: float = 30.0,
    ) -> HttpExchange:
        host = self._assert_host_allowed(url)

        rid = str(uuid.uuid4())
        req = HttpRequest(
            id=rid, method=method, url=url,
            headers={k.lower(): v for k, v in (headers or {}).items()},
            body=body[: self._max_body] if body else None,
            captured_at=datetime.now(tz=timezone.utc).isoformat(),
            surface=classify_surface(method, url, body),
        )

        start = time.monotonic()
        try:
            urllib_req = urllib.request.Request(
                url, method=method, headers=headers or {},
                data=(body.encode("utf-8") if body else None),
            )
            with urllib.request.urlopen(urllib_req, timeout=timeout) as resp:
                raw = resp.read(self._max_body + 1)
                body_text = raw.decode("utf-8", errors="replace")
                if len(body_text) > self._max_body:
                    body_text = body_text[: self._max_body] + "\n[truncated]"
                response_headers = {k.lower(): v for k, v in resp.getheaders()}
                status = resp.status
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")[: self._max_body]
            response_headers = {k.lower(): v for k, v in e.headers.items()}
            status = e.code
        except Exception as e:
            body_text = f"network-error: {e}"
            response_headers = {}
            status = 0

        verdict = self._shield.scan_recalled(body_text) if self._shield_responses else None
        if verdict and verdict.blocked:
            shielded = True
            body_text = f"⟦SHIELDED⟧ {verdict.reason or 'unsafe response body'}"
        else:
            shielded = False

        resp_obj = HttpResponse(
            id=rid, status=status, headers=response_headers,
            body=body_text,
            duration_ms=int((time.monotonic() - start) * 1000),
            received_at=datetime.now(tz=timezone.utc).isoformat(),
            shielded=shielded,
            shield_reason=verdict.reason if verdict and verdict.blocked else None,
        )

        exchange = HttpExchange(
            request=req, response=resp_obj,
            signals=detect_signals(req, resp_obj),
        )
        self._record(exchange)
        return exchange

    def list_exchanges(self) -> list[HttpExchange]:
        return list(self._exchanges)

    def signals(self) -> list[tuple[str, HttpSignal]]:
        return [(e.request.id, s) for e in self._exchanges for s in e.signals]

    def clear(self) -> None:
        self._exchanges.clear()

    def _record(self, e: HttpExchange) -> None:
        self._exchanges.append(e)
        if len(self._exchanges) > self._max_exchanges:
            self._exchanges = self._exchanges[-self._max_exchanges :]

    def _assert_host_allowed(self, url: str) -> str:
        host = urllib.parse.urlparse(url).hostname or ""
        host = host.lower()
        if host in self._deny:
            raise PermissionError(f"host {host} is on the Lyrie proxy deny-list")
        if self._allow is not None and host not in self._allow:
            raise PermissionError(f"host {host} is not on the Lyrie proxy allow-list")
        return host


# ─── Pure helpers ────────────────────────────────────────────────────────────


def classify_surface(method: str, url: str, body: Optional[str] = None) -> str:
    path = urllib.parse.urlparse(url).path.lower() or url.lower()
    blob = (body or "").lower()
    if re.search(r"\b(login|signin|sign-in|auth|sessions)\b", path):
        return "login"
    if re.search(r"\b(register|signup|sign-up|users/create)\b", path):
        return "register"
    if "/logout" in path:
        return "logout"
    if re.search(r"\b(password|reset|forgot)\b", path):
        return "password-reset"
    if path.endswith("/graphql") or "query {" in blob or '"query":' in blob:
        return "graphql"
    if re.search(r"\b(search|q=|search-results)\b", url.lower()):
        return "search"
    if "upload" in path:
        return "upload"
    if "download" in path:
        return "download"
    if re.search(r"\.(html|css|js|png|jpg|gif|svg|woff2?|ico)(\?|$)", path):
        return "static"
    if method == "GET" and re.search(r"/api/\w+/?$", path):
        return "rest-list"
    if method == "GET" and re.search(r"/api/\w+/[\w\-]+", path):
        return "rest-item"
    if "/api" in path:
        return "api-other"
    return "unknown"


_SECURITY_HEADERS = (
    ("content-security-policy", "Content-Security-Policy", "medium"),
    ("strict-transport-security", "Strict-Transport-Security", "high"),
    ("x-content-type-options", "X-Content-Type-Options", "low"),
    ("x-frame-options", "X-Frame-Options or CSP frame-ancestors", "medium"),
    ("referrer-policy", "Referrer-Policy", "low"),
    ("permissions-policy", "Permissions-Policy", "low"),
)


def detect_signals(req: HttpRequest, res: Optional[HttpResponse]) -> list[HttpSignal]:
    if not res:
        return []
    out: list[HttpSignal] = []
    ct = (res.headers.get("content-type") or "").lower()

    if "text/html" in ct:
        csp = (res.headers.get("content-security-policy") or "").lower()
        has_frame_anc = "frame-ancestors" in csp
        for name, desc, sev in _SECURITY_HEADERS:
            if name == "x-frame-options" and has_frame_anc:
                continue
            if name not in res.headers:
                out.append(HttpSignal(
                    kind="missing-security-header",
                    severity=sev,  # type: ignore[arg-type]
                    description=f"Missing {desc} header on HTML response",
                ))

    if res.headers.get("access-control-allow-origin") == "*":
        out.append(HttpSignal(
            kind="open-cors", severity="medium",
            description="Access-Control-Allow-Origin is '*' (wildcard)",
        ))

    set_cookie = res.headers.get("set-cookie")
    if set_cookie:
        lower = set_cookie.lower()
        if "httponly" not in lower:
            out.append(HttpSignal(kind="weak-cookie-flag", severity="medium",
                                  description="Set-Cookie missing HttpOnly flag",
                                  evidence=set_cookie[:120]))
        if req.url.startswith("https://") and "secure" not in lower:
            out.append(HttpSignal(kind="weak-cookie-flag", severity="medium",
                                  description="Set-Cookie missing Secure flag on HTTPS",
                                  evidence=set_cookie[:120]))
        if "samesite" not in lower:
            out.append(HttpSignal(kind="weak-cookie-flag", severity="low",
                                  description="Set-Cookie missing SameSite directive",
                                  evidence=set_cookie[:120]))

    parsed = urllib.parse.urlparse(req.url)
    qs = urllib.parse.parse_qs(parsed.query)
    for param in ("token", "access_token", "auth", "api_key", "apikey", "key"):
        if param in qs:
            out.append(HttpSignal(
                kind="auth-token-in-url", severity="high",
                description=f"Auth-shaped query parameter '{param}' in URL",
            ))

    if res.status >= 500 and re.search(
        r"(stack trace|at \w+ \(|line \d+ in)", res.body or "", re.IGNORECASE
    ):
        out.append(HttpSignal(
            kind="verbose-error", severity="medium",
            description="Server returned a stack-trace-shaped error body on 5xx",
        ))

    if res.body and (
        re.search(r"-----BEGIN (RSA|OPENSSH|PGP|DSA|EC) PRIVATE KEY-----", res.body)
        or re.search(r"\baws_secret_access_key\b", res.body, re.IGNORECASE)
        or re.search(r"\bapi[_-]?key\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}", res.body, re.IGNORECASE)
    ):
        out.append(HttpSignal(
            kind="secret-in-response", severity="critical",
            description="Response body contains credential-shaped material",
        ))

    if req.surface == "graphql" and re.search(r"(__schema|__type)", res.body or ""):
        out.append(HttpSignal(
            kind="graphql-introspection-enabled", severity="medium",
            description="GraphQL introspection appears enabled in production",
        ))

    return out

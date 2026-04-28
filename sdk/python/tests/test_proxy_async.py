"""
Lyrie SDK — async proxy tests (#42).

Tests for HttpProxy.async_send and HttpProxy.async_replay.
Uses pytest-asyncio (via anyio) or a simple asyncio.run() wrapper so the
suite stays runnable without extra plugins when httpx is available.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lyrie.proxy import HttpExchange, HttpProxy, HttpRequest, HttpResponse, Mutator

# ─── Helpers ─────────────────────────────────────────────────────────────────


def run(coro):  # type: ignore[return]
    """Tiny helper so tests run without pytest-asyncio."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_httpx_response(
    status: int = 200,
    body: bytes = b'{"ok": true}',
    headers: Optional[dict] = None,
) -> MagicMock:
    """Build a fake httpx.Response-shaped mock."""
    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.content = body
    mock_resp.headers = {**(headers or {}), "content-type": "application/json"}
    return mock_resp


# ─── async_send ──────────────────────────────────────────────────────────────


def test_async_send_raises_without_httpx() -> None:
    """async_send must raise RuntimeError when httpx is not importable."""
    import lyrie.proxy as proxy_mod

    original = proxy_mod._httpx
    proxy_mod._httpx = None  # type: ignore[assignment]
    try:
        proxy = HttpProxy()
        with pytest.raises(RuntimeError, match="httpx is required"):
            run(proxy.async_send("GET", "https://example.com/"))
    finally:
        proxy_mod._httpx = original


def test_async_send_records_exchange() -> None:
    """async_send stores the exchange and returns it, matching sync send behaviour."""
    try:
        import httpx  # noqa: F401 — skip if not installed
    except ImportError:
        pytest.skip("httpx not installed")

    mock_resp = _make_httpx_response(200, b'{"status":"ok"}')

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        proxy = HttpProxy()
        exchange = run(proxy.async_send("GET", "https://example.com/api/v1"))

    assert isinstance(exchange, HttpExchange)
    assert exchange.request.method == "GET"
    assert exchange.request.url == "https://example.com/api/v1"
    assert exchange.response is not None
    assert exchange.response.status == 200
    assert len(proxy.list_exchanges()) == 1


def test_async_send_deny_host() -> None:
    """async_send must honour the deny-list before making any network call."""
    proxy = HttpProxy(deny_hosts=["blocked.example"])
    with pytest.raises(PermissionError):
        run(proxy.async_send("GET", "https://blocked.example/"))


# ─── async_replay ────────────────────────────────────────────────────────────


def test_async_replay_with_header_mutator() -> None:
    """async_replay forwards mutated headers to async_send."""
    try:
        import httpx  # noqa: F401
    except ImportError:
        pytest.skip("httpx not installed")

    mock_resp = _make_httpx_response(200, b"replayed")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_resp)

    original_exchange = HttpExchange(
        request=HttpRequest(
            id="orig",
            method="GET",
            url="https://example.com/resource",
            headers={"x-original": "yes"},
        ),
        response=HttpResponse(id="orig", status=200, body="original"),
    )

    with patch("httpx.AsyncClient", return_value=mock_client):
        proxy = HttpProxy()
        replayed = run(
            proxy.async_replay(
                original_exchange,
                mutators=[Mutator(kind="header-set", target="x-mutated", value="true")],
            )
        )

    assert isinstance(replayed, HttpExchange)
    assert replayed.response is not None
    assert replayed.response.status == 200
    # The replayed request should carry the mutated header
    assert replayed.request.headers.get("x-mutated") == "true"


# ─── Backward-compat: sync send still works ──────────────────────────────────


def test_sync_send_still_works_deny_host() -> None:
    """The original sync send() must be unaffected by async additions."""
    proxy = HttpProxy(deny_hosts=["blocked.example"])
    with pytest.raises(PermissionError):
        proxy.send("GET", "https://blocked.example/")


def test_sync_send_still_works_allow_host() -> None:
    """sync send() allow-list still works."""
    proxy = HttpProxy(allow_hosts=["allowed.example"])
    with pytest.raises(PermissionError):
        proxy.send("GET", "https://other.example/")

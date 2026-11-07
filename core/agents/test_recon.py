"""Unit tests for the Recon Agent — all three discovery paths, MOCKED (no Docker).

Run: pytest core/agents/test_recon.py
"""
from __future__ import annotations

import httpx
import pytest

from core.agents import recon

BASE = "http://target"


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


# --- 1. OpenAPI path ------------------------------------------------------- #

async def test_parse_openapi_spec_passed_in():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://target/api/v1"}],
        "security": [{"bearer": []}],
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
                "get": {"responses": {}},
            },
            "/login": {
                "post": {
                    "security": [],
                    "requestBody": {"content": {"application/json": {"schema": {
                        "properties": {"email": {"type": "string"}, "password": {"type": "string"}}}}}},
                },
            },
        },
    }
    surface = await recon.recon(BASE, openapi_spec=spec)
    by_url = {(e.method, e.url): e for e in surface.endpoints}

    get_user = by_url[("GET", "http://target/api/v1/users/{id}")]
    assert get_user.auth_required is True  # inherits global security
    assert any(p.location == "path" and p.name == "id" and p.type == "integer" for p in get_user.params)

    login = by_url[("POST", "http://target/api/v1/login")]
    assert login.auth_required is False  # op-level security [] overrides
    assert {p.name for p in login.params} == {"email", "password"}
    assert all(p.location == "body" for p in login.params)


async def test_discovery_rejects_spa_shell_then_falls_back_to_crawl():
    """An SPA returns 200 HTML for /openapi.json — must NOT be parsed as a spec."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html='<html><body><form method="post" action="/feedback">'
                                             '<input name="comment"><input name="rating" type="number">'
                                             '</form></body></html>')
        # Every other path (incl. all spec paths) returns the SPA shell.
        return httpx.Response(200, html="<!doctype html><html><app-root></app-root></html>")

    async with _client(handler) as c:
        surface = await recon.recon(BASE, scan_assets=False, http_client=c)

    # Fell back to crawl; found the feedback form, not a bogus spec endpoint.
    fb = [e for e in surface.endpoints if e.url.endswith("/feedback")]
    assert fb and fb[0].method == "POST"
    assert {p.name for p in fb[0].params} == {"comment", "rating"}
    assert all(p.location == "body" for p in fb[0].params)
    assert next(p for p in fb[0].params if p.name == "rating").type == "int"


# --- 2. Crawl path --------------------------------------------------------- #

async def test_crawl_extracts_anchor_query_params():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html='<a href="/search?q=test&page=2">s</a>')
        return httpx.Response(404)

    async with _client(handler) as c:
        surface = await recon.recon(BASE, scan_assets=False, http_client=c)

    search = [e for e in surface.endpoints if e.url.endswith("/search")]
    assert search and search[0].method == "GET"
    assert {p.name for p in search[0].params} == {"q", "page"}
    assert next(p for p in search[0].params if p.name == "page").type == "int"


# --- 3. Asset scan path ---------------------------------------------------- #

async def test_asset_scan_recovers_spa_api_paths():
    js = 'const a=this.host+"api/Products";const b="rest/basket";xhr("rest/user/login")'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html='<html><script src="/main.js"></script></html>')
        if request.url.path == "/main.js":
            return httpx.Response(200, text=js, headers={"content-type": "application/javascript"})
        return httpx.Response(404)

    async with _client(handler) as c:
        surface = await recon.recon(BASE, http_client=c)

    urls = {(e.method, e.url) for e in surface.endpoints}
    assert ("GET", "http://target/api/Products") in urls
    assert ("GET", "http://target/rest/basket") in urls
    assert ("GET", "http://target/rest/user/login") in urls
    # /api/<Model> collection convention expands to create + item-by-id.
    assert ("POST", "http://target/api/Products") in urls
    assert ("GET", "http://target/api/Products/:id") in urls
    item = next(e for e in surface.endpoints if e.url == "http://target/api/Products/:id")
    assert any(p.location == "path" and p.name == "id" for p in item.params)

"""Recon Agent — maps a target's attack surface (03_AGENTS.md, Phase 2).

Deterministic-first, NO LLM. Three discovery paths, tried in order of reliability:

1. OpenAPI/Swagger spec — if one is passed in, or discoverable at a common path.
   The body is validated as real JSON with an ``openapi``/``swagger`` key, so an SPA
   that serves ``index.html`` (HTTP 200) for unknown routes does not fool us.
2. HTML crawl — httpx + BeautifulSoup BFS over same-origin pages up to a depth limit:
   forms (→ body/query params) and anchors carrying query strings.
3. Asset path scan — same-origin JS bundles are scanned with a regex for ``/api/..``
   and ``/rest/..`` path literals. This is how a single-page app's REST surface is
   recovered deterministically. LLM-assisted inference of undocumented endpoints
   remains a v2 enhancement (03_AGENTS.md) and is intentionally NOT done here.

Output: ``AttackSurfaceMap`` (schemas/models.py). Param types/locations are inferred
conservatively; request bodies for custom endpoints are left to later phases rather
than fabricated.
"""
from __future__ import annotations

import json
import re
from collections import deque
from typing import Any, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from schemas.models import AttackSurfaceMap, Endpoint, ParamSchema

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}

COMMON_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs",
    "/api-docs", "/api-docs/swagger.json", "/api/openapi.json",
]

# Matches path fragments like "api/Users", "rest/basket", "rest/products/search",
# with optional leading slash and :id / {id} template segments.
_API_PATH_RE = re.compile(r"/?((?:api|rest)/[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_:{}\-]+)*)")
_API_MODEL_RE = re.compile(r"^/api/[A-Z][A-Za-z0-9]+$")  # Sequelize auto-CRUD collection


# --------------------------------------------------------------------------- #
# Param helpers
# --------------------------------------------------------------------------- #

def _infer_type(name: str, html_input_type: Optional[str] = None, sample: Optional[str] = None) -> str:
    if html_input_type:
        t = html_input_type.lower()
        if t in ("number", "range"):
            return "int"
        if t == "file":
            return "file"
        if t == "email":
            return "string"
    if sample is not None and sample.isdigit():
        return "int"
    low = name.lower()
    if low == "id" or low.endswith("id") or low.endswith("_id"):
        return "int"
    return "string"


def _path_params(url_path: str) -> list[ParamSchema]:
    """Extract :name / {name} path-template params."""
    params: list[ParamSchema] = []
    for seg in url_path.split("/"):
        name = None
        if seg.startswith(":"):
            name = seg[1:]
        elif seg.startswith("{") and seg.endswith("}"):
            name = seg[1:-1]
        if name:
            params.append(ParamSchema(name=name, location="path", type=_infer_type(name)))
    return params


# --------------------------------------------------------------------------- #
# 1. OpenAPI / Swagger
# --------------------------------------------------------------------------- #

async def _discover_spec(client: httpx.AsyncClient, base_url: str) -> Optional[dict[str, Any]]:
    for path in COMMON_SPEC_PATHS:
        try:
            resp = await client.get(urljoin(base_url, path))
        except httpx.HTTPError:
            continue
        if resp.status_code != 200:
            continue
        # Reject the SPA shell: must parse as JSON AND look like a spec.
        try:
            doc = json.loads(resp.text)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and "paths" in doc:
            return doc
    return None


def _openapi_base_prefix(spec: dict[str, Any]) -> str:
    # OpenAPI 3 servers[].url path, or Swagger 2 basePath.
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        return urlparse(servers[0].get("url", "")).path.rstrip("/")
    return (spec.get("basePath") or "").rstrip("/")


def _parse_openapi(spec: dict[str, Any], base_url: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    prefix = _openapi_base_prefix(spec)
    global_security = bool(spec.get("security"))
    base = base_url.rstrip("/")

    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters", [])
        for method, op in item.items():
            if method.upper() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params: list[ParamSchema] = []
            for p in list(shared_params) + op.get("parameters", []):
                loc = p.get("in")
                if loc == "formData":
                    loc = "body"
                if loc not in ("query", "path", "header", "cookie", "body"):
                    continue
                schema = p.get("schema", {})
                ptype = schema.get("type") or p.get("type") or "string"
                params.append(ParamSchema(name=p.get("name", "?"), location=loc, type=ptype))
            # OpenAPI 3 requestBody JSON properties → body params.
            body = op.get("requestBody", {})
            content = body.get("content", {}) if isinstance(body, dict) else {}
            json_schema = (content.get("application/json", {}) or {}).get("schema", {})
            for prop, pschema in (json_schema.get("properties", {}) or {}).items():
                params.append(ParamSchema(name=prop, location="body",
                                          type=pschema.get("type", "string")))

            # OpenAPI: op-level `security` overrides global. Absent → inherit global;
            # present-but-empty ([]) → auth explicitly disabled for this operation.
            op_security = op.get("security")
            auth_required = bool(op_security) if op_security is not None else global_security
            endpoints.append(Endpoint(
                url=base + prefix + path,
                method=method.upper(),  # type: ignore[arg-type]
                params=params,
                auth_required=auth_required,
            ))
    return endpoints


# --------------------------------------------------------------------------- #
# 2. HTML crawl
# --------------------------------------------------------------------------- #

async def _crawl(client: httpx.AsyncClient, base_url: str, max_depth: int, max_pages: int) -> list[Endpoint]:
    host = urlparse(base_url).netloc
    seen_pages: set[str] = set()
    endpoints: list[Endpoint] = []
    queue: deque[tuple[str, int]] = deque([(base_url, 0)])

    while queue and len(seen_pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen_pages or depth > max_depth:
            continue
        seen_pages.add(url)
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if "html" not in resp.headers.get("content-type", ""):
            continue
        soup = BeautifulSoup(resp.text, "html.parser")

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method not in HTTP_METHODS:
                method = "GET"
            action = urljoin(url, form.get("action") or url)
            loc = "body" if method in ("POST", "PUT", "PATCH") else "query"
            params = []
            for field in form.find_all(["input", "select", "textarea"]):
                name = field.get("name")
                if name:
                    params.append(ParamSchema(name=name, location=loc,
                                              type=_infer_type(name, field.get("type"))))
            endpoints.append(Endpoint(url=action, method=method, params=params))  # type: ignore[arg-type]

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if urlparse(link).netloc != host:
                continue
            qs = urlparse(link).query
            if qs:
                params = [ParamSchema(name=k, location="query", type=_infer_type(k, sample=v))
                          for k, v in parse_qsl(qs)]
                endpoints.append(Endpoint(url=link.split("?")[0], method="GET", params=params))
            elif depth + 1 <= max_depth:
                queue.append((link, depth + 1))

    return endpoints


# --------------------------------------------------------------------------- #
# 3. Asset (JS bundle) path scan — deterministic
# --------------------------------------------------------------------------- #

async def _scan_assets(client: httpx.AsyncClient, base_url: str) -> list[Endpoint]:
    try:
        root = await client.get(base_url)
    except httpx.HTTPError:
        return []
    soup = BeautifulSoup(root.text, "html.parser")
    host = urlparse(base_url).netloc

    fragments: set[str] = set()
    for script in soup.find_all("script", src=True):
        src = urljoin(base_url, script["src"])
        if urlparse(src).netloc != host or not src.split("?")[0].endswith(".js"):
            continue
        try:
            js = (await client.get(src)).text
        except httpx.HTTPError:
            continue
        fragments.update(m.group(1) for m in _API_PATH_RE.finditer(js))

    endpoints: list[Endpoint] = []
    for frag in sorted(fragments):
        path = "/" + frag
        endpoints.append(Endpoint(url=base_url.rstrip("/") + path, method="GET",
                                  params=_path_params(path)))
        # REST collection convention (/api/<Model>): add create + item-by-id endpoints.
        if _API_MODEL_RE.match(path):
            coll = base_url.rstrip("/") + path
            item = coll + "/:id"
            endpoints.append(Endpoint(url=coll, method="POST", params=[]))
            endpoints.append(Endpoint(url=item, method="GET",
                                      params=[ParamSchema(name="id", location="path", type="int")]))
    return endpoints


# --------------------------------------------------------------------------- #
# Dedupe + public entrypoint
# --------------------------------------------------------------------------- #

def _dedupe(endpoints: list[Endpoint]) -> list[Endpoint]:
    merged: dict[tuple[str, str], Endpoint] = {}
    for ep in endpoints:
        key = (ep.method, ep.url)
        if key not in merged:
            merged[key] = ep
            continue
        existing = {(p.name, p.location) for p in merged[key].params}
        for p in ep.params:
            if (p.name, p.location) not in existing:
                merged[key].params.append(p)
    return sorted(merged.values(), key=lambda e: (e.url, e.method))


async def recon(
    target_base_url: str,
    openapi_spec: dict[str, Any] | None = None,
    *,
    max_depth: int = 2,
    max_pages: int = 40,
    scan_assets: bool = True,
    http_client: httpx.AsyncClient | None = None,
) -> AttackSurfaceMap:
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30, follow_redirects=True)
    try:
        spec = openapi_spec or await _discover_spec(client, target_base_url)
        if spec:
            endpoints = _parse_openapi(spec, target_base_url)
        else:
            endpoints = await _crawl(client, target_base_url, max_depth, max_pages)
            if scan_assets:
                endpoints += await _scan_assets(client, target_base_url)
        return AttackSurfaceMap(target_base_url=target_base_url, endpoints=_dedupe(endpoints))
    finally:
        if owns_client:
            await client.aclose()

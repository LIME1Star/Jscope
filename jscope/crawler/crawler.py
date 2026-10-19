"""Crawl Mode: discover a site's client-side artifacts from a live URL. Download-only, no analysis (PRD section 6).

Phase 4 widened this from "JavaScript only" to everything the analyzers can read:
  - the page itself (HTML: forms, inline scripts)                        kind=html
  - <script src>, static imports inside discovered JS (one hop), manifests  kind=js
  - *.wasm references found in the page or in discovered JS               kind=wasm
  - well-known API-description paths (openapi.json, swagger.json, /v3/api-docs, schema.graphql ...), GET only.
    A probe is kept ONLY if the response really is an OpenAPI document or GraphQL schema, so single-page apps that answer
    200/HTML for every path do not litter the project with junk. Disable probing with probe=False (`--no-probe`).

Limits, stated honestly: dynamic import() paths built at runtime are not resolved; GraphQL introspection is a POST and is
never done here; only the one page you name is fetched (no link following).
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from jscope.core.artifacts import KIND_GRAPHQL_SCHEMA, KIND_OPENAPI, classify_artifact
from jscope.security_transport import GuardedSession, TransportPolicy, normalize_host, PolicyError

DEFAULT_UA = "JScope/0.4 (+https://github.com/jscope)"

_STATIC_IMPORT_RE = re.compile(r"""import\s*(?:[^'"]*from\s*)?['"]([^'"]+\.js[^'"]*)['"]""")
_DYNAMIC_IMPORT_RE = re.compile(r"""import\(\s*['"]([^'"]+\.js[^'"]*)['"]\s*\)""")
_WASM_RE = re.compile(r"""['"(=\s]([A-Za-z0-9_@./%+-]+\.wasm)(?:\?[^'")\s]*)?""")

WELL_KNOWN_SPECS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/v3/api-docs", "/v2/api-docs", "/api-docs",
    "/api/openapi.json", "/api/swagger.json", "/api/v1/openapi.json", "/swagger/v1/swagger.json",
    "/schema.graphql", "/schema.gql", "/graphql/schema.graphql",
)
_RETRY_STATUS = (502, 503, 504)
_MAX_PROBE_BYTES = 8 * 1024 * 1024


class CrawlError(Exception):
    """A user-facing failure (unreachable site, HTTP error) -- never a traceback."""


@dataclass
class DiscoveredAsset:
    url: str
    source: str        # "page" | "script_tag" | "module_import" | "manifest" | "wasm_reference" | "well_known_path"
    kind: str = "js"   # "html" | "js" | "wasm" | "openapi" | "graphql_schema"


def _get(session, url: str, timeout: int, retries: int = 2) -> requests.Response:
    """GET with a short retry for flaky/overloaded sites (connection errors and 502/503/504)."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException as exc:
            last = exc
        else:
            if resp.status_code in _RETRY_STATUS and attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            return resp
        if attempt < retries:
            time.sleep(1.5 * (attempt + 1))
    raise CrawlError(f"could not reach {url}: {type(last).__name__}: {last}")


def _explain_status(status: int) -> str:
    if status in _RETRY_STATUS:
        return "the site is down or overloaded right now, or it is rejecting automated requests; try again later and confirm it loads in a browser"
    if status in (401, 403):
        return "the site refuses this request (login wall, WAF or bot protection); JScope does not bypass that"
    if status == 404:
        return "no page at that URL; check the address"
    if status == 429:
        return "rate limited; wait and retry"
    return "unexpected response"


def _probe_kind(path: str, data: bytes) -> str | None:
    low = path.lower()
    ext = ".yaml" if low.endswith((".yaml", ".yml")) else ".graphql" if low.endswith((".graphql", ".gql")) else ".json"
    kind = classify_artifact("probe" + ext, data)
    return kind if kind in (KIND_OPENAPI, KIND_GRAPHQL_SCHEMA) else None


def discover(target_url: str, timeout: int = 15, user_agent: str = DEFAULT_UA, probe: bool = True, policy: TransportPolicy | None = None) -> list[DiscoveredAsset]:
    if not urlparse(target_url).scheme:
        target_url = "https://" + target_url
    if policy is None:
        parsed = urlparse(target_url)
        if not parsed.hostname:
            raise CrawlError("target URL has no valid hostname")
        # Default scope is the explicitly supplied target host; expansion requires a caller-supplied policy.
        policy = TransportPolicy(hosts={normalize_host(parsed.hostname)}, assessment_id="crawl-" + normalize_host(parsed.hostname), timeout=timeout, max_response_bytes=_MAX_PROBE_BYTES, total_budget=100, retries=0)
    session = GuardedSession(policy)
    session.session.headers.update({"User-Agent": user_agent})
    found: dict[str, DiscoveredAsset] = {}

    try:
        resp = _get(session, target_url, timeout)
    except PolicyError as exc:
        raise CrawlError(f"request blocked by scope policy: {exc}") from exc
    if resp.status_code >= 400:
        raise CrawlError(f"{target_url} answered HTTP {resp.status_code}: {_explain_status(resp.status_code)}")
    final_url = resp.url or target_url
    found[final_url] = DiscoveredAsset(url=final_url, source="page", kind="html")
    soup = BeautifulSoup(resp.text, "html.parser")

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            full = urljoin(final_url, src)
            found.setdefault(full, DiscoveredAsset(url=full, source="script_tag"))

    for manifest_path in ("/asset-manifest.json", "/manifest.json"):          # CRA/webpack convention
        try:
            m_resp = session.get(urljoin(final_url, manifest_path), timeout=timeout)
            if m_resp.ok and "json" in m_resp.headers.get("content-type", ""):
                for v in _walk_strings(m_resp.json()):
                    if v.endswith(".js"):
                        full = urljoin(final_url, v)
                        found.setdefault(full, DiscoveredAsset(url=full, source="manifest"))
        except (requests.RequestException, ValueError):
            pass

    for m in _WASM_RE.finditer(resp.text):
        full = urljoin(final_url, m.group(1))
        found.setdefault(full, DiscoveredAsset(url=full, source="wasm_reference", kind="wasm"))

    for js_url in [a.url for a in found.values() if a.kind == "js"]:           # one hop into discovered JS
        try:
            js_resp = session.get(js_url, timeout=timeout)
            if not js_resp.ok:
                continue
        except requests.RequestException:
            continue
        for pattern in (_STATIC_IMPORT_RE, _DYNAMIC_IMPORT_RE):
            for m in pattern.finditer(js_resp.text):
                full = urljoin(js_url, m.group(1))
                found.setdefault(full, DiscoveredAsset(url=full, source="module_import"))
        for m in _WASM_RE.finditer(js_resp.text):
            full = urljoin(js_url, m.group(1))
            found.setdefault(full, DiscoveredAsset(url=full, source="wasm_reference", kind="wasm"))

    if probe:
        base = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
        for path in WELL_KNOWN_SPECS:
            url = base + path
            try:
                r = session.get(url, timeout=timeout)
            except requests.RequestException:
                continue
            if r.status_code != 200 or len(r.content) > _MAX_PROBE_BYTES:
                continue
            kind = _probe_kind(path, r.content)
            if kind:
                found.setdefault(url, DiscoveredAsset(url=url, source="well_known_path", kind=kind))
    session.close()
    return list(found.values())


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)

"""Download Mode: text file of URLs -> project directory (JS, HTML, specs, schemas, WASM).
Dedupes by content hash, preserves metadata (source URL, fetch time, status).
No analysis happens here (PRD §6: crawling/downloading produce no findings)."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests
from jscope.security_transport import GuardedSession, TransportPolicy, PolicyError, normalize_host

DEFAULT_TIMEOUT = 15
DEFAULT_UA = "JScope/0.4 (+https://github.com/jscope)"


class DownloadError(Exception):
    """A user-facing failure (bad input file) -- never a traceback."""


def extension_for(url: str, content: bytes, content_type: str = "") -> str:
    """Pick the saved file's extension from what the bytes ARE, so the analyzers' content sniffing sees the right kind."""
    path = urlparse(url).path.lower()
    ctype = content_type.lower()
    if content[:4] == b"\x00asm":
        return ".wasm"
    if path.endswith((".js", ".mjs", ".cjs", ".jsx")) or "javascript" in ctype:
        return ".js"
    head = content[:512].lstrip().lower()
    if "html" in ctype or head.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return ".html"
    if path.endswith((".yaml", ".yml")) or "yaml" in ctype:
        return ".yaml"
    if path.endswith((".graphql", ".gql", ".graphqls")):
        return ".graphql"
    if "json" in ctype or head.startswith((b"{", b"[")):
        return ".json"
    return ".js"


@dataclass
class DownloadResult:
    url: str
    ok: bool
    path: str | None = None
    error: str | None = None
    status_code: int | None = None
    duplicate_of: str | None = None


def download_urls(url_file: str, out_dir: str, timeout: int = DEFAULT_TIMEOUT,
                   user_agent: str = DEFAULT_UA, policy: TransportPolicy | None = None) -> list[DownloadResult]:
    if policy is None:
        raise DownloadError("network downloads require an explicit assessment TransportPolicy; refusing unguarded URL-list downloads")
    try:
        text = Path(url_file).read_text()
    except OSError as exc:
        raise DownloadError(f"cannot read URL list {url_file!r}: {exc.strerror or exc}. "
                            f"Create it first with `jscope crawl <url> --out {url_file}`.") from exc
    urls = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    urls = list(dict.fromkeys(urls))  # de-dupe identical URL strings, preserve order

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    meta_path = out_path / "_jscope_meta.json"
    meta: dict[str, dict] = {}
    seen_hashes: dict[str, str] = {}  # content_hash -> first filename
    results: list[DownloadResult] = []

    session = GuardedSession(policy)
    session.session.headers.update({"User-Agent": user_agent})

    for i, url in enumerate(urls):
        try:
            resp = session.get(url, timeout=timeout)
        except (requests.RequestException, PolicyError) as e:
            results.append(DownloadResult(url=url, ok=False, error=str(e)))
            continue

        if resp.status_code != 200:
            results.append(DownloadResult(url=url, ok=False, status_code=resp.status_code,
                                           error=f"HTTP {resp.status_code}"))
            resp.close()
            continue

        content = resp.content
        resp.close()
        content_hash = hashlib.sha256(content).hexdigest()[:16]

        if content_hash in seen_hashes:
            results.append(DownloadResult(url=url, ok=True, duplicate_of=seen_hashes[content_hash]))
            continue

        safe_name = f"{i:05d}_{content_hash}{extension_for(url, content, resp.headers.get('Content-Type', ''))}"
        (out_path / safe_name).write_bytes(content)
        seen_hashes[content_hash] = safe_name
        meta[safe_name] = {
            "source_url": url,
            "fetched_at": time.time(),
            "status_code": resp.status_code,
            "content_hash": content_hash,
            "bytes": len(content),
        }
        results.append(DownloadResult(url=url, ok=True, path=str(out_path / safe_name),
                                       status_code=resp.status_code))

    meta_path.write_text(json.dumps(meta, indent=2))
    session.close()
    return results

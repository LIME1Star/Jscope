"""Scan scope and runtime safety (FR-10).

One policy object answers "may JScope talk to this destination?" for EVERY outbound request the runtime layer makes
(confirm, observe, verify). It checks, in this order:
  scheme -> host allow-list -> port allow-list -> DNS resolution -> every resolved address against the
  loopback/private/link-local/multicast/reserved/metadata deny-list (unless `allow_private` was granted for a controlled
  local test) -> redirect target (same rules, plus `redirects` mode).

DNS-rebinding defence: the destination is resolved ONCE, validated, and then the connection is pinned to the validated
address (`PinnedSession`). A name that resolves to a public address when checked and to 127.0.0.1 when connected to
cannot happen, because there is no second resolution. TLS still verifies the original hostname.

Static analysis never imports this module's network pieces.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlparse

Resolver = Callable[[str, int], list[str]]


def _redact(text: str) -> str:
    from jscope.core.redact import redact_text, redact_url
    return redact_url(text) if text.startswith(("http://", "https://")) else (redact_text(text) or "")


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


class ScopeViolation(ValueError):
    """The destination is outside the configured scope. Never a network error: nothing was sent."""


class EmergencyStopped(RuntimeError):
    pass


@dataclass
class BlockedRequest:
    url: str
    reason: str
    at: float = field(default_factory=time.time)


def _is_prohibited(ip_text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(ip_text.split("%")[0])
    except ValueError:
        return "unparseable address"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for name in ("is_loopback", "is_private", "is_link_local", "is_multicast", "is_reserved", "is_unspecified"):
        if getattr(ip, name):
            return name[3:].replace("_", " ")
    if ip_text in ("169.254.169.254", "fd00:ec2::254"):
        return "cloud metadata address"
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "carrier-grade NAT"
    return None


class EmergencyStop:
    """Process-wide kill switch for active tests. Trips via `.trip()`, a sentinel file (`jscope stop`), or SIGINT handlers
    that call trip(). Every request checks it BEFORE sending."""
    DEFAULT_FILE = ".jscope-stop"

    def __init__(self, stop_file: str | None = None):
        self._ev = threading.Event()
        self.stop_file = stop_file or os.environ.get("JSCOPE_STOP_FILE") or self.DEFAULT_FILE
        self.reason = ""

    def trip(self, reason: str = "emergency stop requested") -> None:
        self.reason = reason
        self._ev.set()

    def is_set(self) -> bool:
        if not self._ev.is_set() and self.stop_file and os.path.exists(self.stop_file):
            self.trip(f"stop file {self.stop_file!r} present")
        return self._ev.is_set()

    def check(self) -> None:
        if self.is_set():
            raise EmergencyStopped(self.reason or "emergency stop")

    def clear(self) -> None:
        self._ev.clear()
        self.reason = ""


@dataclass
class ScopePolicy:
    allow_hosts: set[str]
    schemes: tuple[str, ...] = ("http", "https")
    ports: set[int] | None = None                  # None => default ports of the scheme only
    redirects: str = "same-scope"                  # "none" | "same-scope"
    max_redirects: int = 3
    allow_private: bool = False                    # explicit opt-in for a controlled local/lab target
    resolver: Resolver = system_resolver
    blocked: list[BlockedRequest] = field(default_factory=list)
    rate_per_second: float = 2.0
    max_requests: int = 100
    timeout: float = 8.0
    stop: EmergencyStop = field(default_factory=EmergencyStop)

    def __post_init__(self):
        self.allow_hosts = {h.lower() for h in self.allow_hosts if h}
        self.sent = 0
        self._last = 0.0

    # -- checks ------------------------------------------------------------------------------------------
    def _host_allowed(self, host: str, port: int | None) -> bool:
        host = host.lower()
        if host in self.allow_hosts:
            return True
        return port is not None and f"{host}:{port}" in self.allow_hosts

    def check_url(self, url: str, resolve: bool = True) -> list[str]:
        """Return the validated addresses the connection may use, or raise ScopeViolation (and log the block)."""
        try:
            return self._check(url, resolve)
        except ScopeViolation as exc:
            self.blocked.append(BlockedRequest(url, str(exc)))
            raise

    def _check(self, url: str, resolve: bool) -> list[str]:
        u = urlparse(url)
        if u.scheme not in self.schemes:
            raise ScopeViolation(f"scheme {u.scheme!r} is not allowed (allowed: {', '.join(self.schemes)})")
        host = (u.hostname or "").lower()
        if not host:
            raise ScopeViolation("no host in URL")
        if u.username or u.password:
            raise ScopeViolation("credentials in the URL are not allowed")
        port = u.port or (443 if u.scheme == "https" else 80)
        default_port = u.port is None
        if not self._host_allowed(host, u.port if u.port else None) and not self._host_allowed(host, port):
            raise ScopeViolation(f"host {host!r} is not in the allow-list {sorted(self.allow_hosts)}")
        if self.ports is not None:
            if port not in self.ports:
                raise ScopeViolation(f"port {port} is not allowed (allowed: {sorted(self.ports)})")
        elif not default_port and f"{host}:{port}" not in self.allow_hosts:
            raise ScopeViolation(f"non-default port {port} requires listing '{host}:{port}' in the allow-list or --allow-port")
        # literal IPs are checked directly; names are resolved and EVERY answer is checked
        try:
            ipaddress.ip_address(host)
            addrs = [host]
        except ValueError:
            addrs = self.resolver(host, port) if resolve else []
            if resolve and not addrs:
                raise ScopeViolation(f"{host!r} did not resolve to any address")
        if not self.allow_private:
            for a in addrs:
                why = _is_prohibited(a)
                if why:
                    raise ScopeViolation(f"{host!r} resolves to {a} ({why}); local/private destinations need explicit --allow-private")
        return addrs

    def check_redirect(self, current_url: str, location: str, hops: int) -> str:
        if self.redirects == "none":
            raise ScopeViolation("redirects are disabled by policy")
        if hops >= self.max_redirects:
            raise ScopeViolation(f"more than {self.max_redirects} redirects")
        target = urljoin(current_url, location)
        self.check_url(target)                       # same checks as any request: scheme, host, port, DNS, address class
        return target

    # -- pacing --------------------------------------------------------------------------------------------
    def before_send(self, sleep: Callable[[float], None] = time.sleep) -> None:
        self.stop.check()
        if self.sent >= self.max_requests:
            raise ScopeViolation("request cap reached")
        gap = 1.0 / self.rate_per_second if self.rate_per_second > 0 else 0
        wait = gap - (time.monotonic() - self._last)
        if wait > 0:
            sleep(wait)
        self.stop.check()
        self._last = time.monotonic()
        self.sent += 1

    def describe(self) -> dict:
        return {"allow_hosts": sorted(self.allow_hosts), "schemes": list(self.schemes), "ports": sorted(self.ports) if self.ports else "default",
                "redirects": self.redirects, "allow_private": self.allow_private, "rate_per_second": self.rate_per_second,
                "max_requests": self.max_requests, "blocked": [{"url": _redact(b.url), "reason": _redact(b.reason)} for b in self.blocked]}


# ---------------------------------------------------------------------------------------------- pinned connections
_pin_lock = threading.RLock()
_pins: dict[str, str] = {}
_orig_create_connection = None


def _install_pin_hook():
    global _orig_create_connection
    from urllib3.util import connection as u3conn
    if _orig_create_connection is not None:
        return
    _orig_create_connection = u3conn.create_connection

    def pinned(address, *a, **kw):
        host, port = address
        ip = _pins.get(str(host).lower())
        return _orig_create_connection((ip, port) if ip else address, *a, **kw)
    u3conn.create_connection = pinned


class pinned_dns:
    """Context manager: connections to `host` go to `ip` (already validated) and nowhere else, whatever DNS says later."""
    def __init__(self, host: str, ip: str | None):
        self.host, self.ip = host.lower(), ip

    def __enter__(self):
        _pin_lock.acquire()
        _install_pin_hook()
        if self.ip:
            _pins[self.host] = self.ip
        return self

    def __exit__(self, *exc):
        _pins.pop(self.host, None)
        _pin_lock.release()


@dataclass
class ScopedResponse:
    status: int
    content_type: str = ""
    length: int = 0
    headers: dict = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)
    body: bytes = b""
    url: str = ""
    redirects: list = field(default_factory=list)       # [(from_url, status, to_url)]


class ScopedClient:
    """The only HTTP client the runtime layer uses. Validates, pins, paces, follows redirects manually inside scope."""

    def __init__(self, policy: ScopePolicy, headers: dict | None = None,
                 transport: Callable[[str, str, dict, float, int], ScopedResponse] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.policy = policy
        self.headers = {"User-Agent": "jscope/0.5 (authorized security testing)", "Accept": "*/*", **(headers or {})}
        self._transport = transport
        self._sleep = sleep

    def request(self, method: str, url: str, headers: dict | None = None, follow: bool = False, body_limit: int = 65536) -> ScopedResponse:
        hops, trail = 0, []
        h = {**self.headers, **(headers or {})}
        while True:
            addrs = self.policy.check_url(url, resolve=self._transport is None)
            self.policy.before_send(self._sleep)
            r = self._send(method, url, h, addrs, body_limit)
            r.url = url
            loc = r.headers.get("location")
            if follow and 300 <= r.status < 400 and loc:
                target = self.policy.check_redirect(url, loc, hops)
                trail.append((url, r.status, target))
                hops += 1
                url = target
                continue
            r.redirects = trail
            return r

    def _send(self, method: str, url: str, headers: dict, addrs: list[str], body_limit: int) -> ScopedResponse:
        if self._transport is not None:
            return self._transport(method, url, headers, self.policy.timeout, body_limit)
        import requests
        host = urlparse(url).hostname or ""
        ip = addrs[0] if addrs else None
        with pinned_dns(host, ip):
            r = requests.request(method, url, headers=headers, timeout=self.policy.timeout, allow_redirects=False, stream=True)
            try:
                body = r.raw.read(body_limit, decode_content=True) if method == "GET" else b""
                cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
            finally:
                r.close()
        return ScopedResponse(r.status_code, r.headers.get("Content-Type", ""), int(r.headers.get("Content-Length") or len(body)),
                              {k.lower(): v for k, v in r.headers.items()}, list(cookies), body)

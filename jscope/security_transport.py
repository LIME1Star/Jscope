"""Assessment-bound URL validation and guarded Requests transport.

This is an enforcement adapter for requests-based HTTP paths. Callers must supply
an explicit root/approved host set; redirects are handled manually and revalidated.
DNS checks reduce SSRF risk but requests' standard resolver is not connection-pinned,
so DNS rebinding/TOCTOU protection is not guaranteed by this adapter.
"""
from __future__ import annotations
import hashlib, ipaddress, json, socket, time, threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import url2pathname
import requests

class PolicyError(ValueError):
    def __init__(self, reason: str, url: str = ""):
        self.reason, self.url = reason, url
        super().__init__(f"{reason}: {redact_url(url)}" if url else reason)

def normalize_host(host: str) -> str:
    if not isinstance(host, str) or not host or '%' in host:
        raise PolicyError('invalid-host')
    host = host.rstrip('.').lower()
    try:
        return ipaddress.ip_address(host.strip('[]')).compressed
    except ValueError:
        try:
            import idna
            host = idna.encode(host, uts46=True, std3_rules=True).decode('ascii').lower()
        except ImportError:
            try: host = host.encode('idna').decode('ascii').lower()
            except UnicodeError as e: raise PolicyError('invalid-idn') from e
        if len(host) > 253 or not host or any(not x or len(x)>63 for x in host.split('.')):
            raise PolicyError('invalid-host')
        if any(not __import__('re').fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', x) for x in host.split('.')):
            raise PolicyError('invalid-host')
        return host

def redact_url(url: str) -> str:
    try:
        p=urlsplit(url)
        host=p.hostname or ''
        return urlunsplit((p.scheme, host + ((':'+str(p.port)) if p.port else ''), p.path, '[redacted]' if p.query else '', ''))
    except Exception: return '[invalid-url]'

def validate_url(url: str, hosts: set[str], schemes=('http','https'), ports=None, allow_subdomains=True) -> str:
    if not isinstance(url,str) or any(ord(c)<32 for c in url): raise PolicyError('malformed-url', str(url))
    try:
        p=urlsplit(url)
        if p.scheme.lower() not in schemes: raise PolicyError('scheme-not-allowed',url)
        if not p.netloc or not p.hostname: raise PolicyError('missing-host',url)
        if p.username is not None or p.password is not None or '@' in p.netloc: raise PolicyError('userinfo-not-allowed',url)
        host=normalize_host(p.hostname)
        port=p.port
        if port is not None and not 1 <= port <= 65535: raise PolicyError('invalid-port',url)
        effective=port or (443 if p.scheme.lower()=='https' else 80)
        if ports is not None and effective not in ports: raise PolicyError('port-not-allowed',url)
        normalized={normalize_host(h) for h in hosts}
        if not any(host == h or (allow_subdomains and host.endswith('.'+h)) for h in normalized): raise PolicyError('host-out-of-scope',url)
        # reject ambiguous authority and malformed percent escapes in authority
        if '%' in p.netloc: raise PolicyError('malformed-authority',url)
        return urlunsplit((p.scheme.lower(), (f'[{host}]' if ':' in host else host) + (f':{port}' if port else ''), p.path or '/', p.query, ''))
    except PolicyError: raise
    except (ValueError, UnicodeError) as e: raise PolicyError('malformed-url',url) from e

@dataclass
class TransportPolicy:
    hosts: set[str]
    assessment_id: str
    allow_private: bool = False
    allow_loopback: bool = False
    allow_link_local: bool = False
    schemes: tuple[str,...] = ('http','https')
    ports: set[int] | None = None
    timeout: float = 10.0
    max_redirects: int = 5
    max_response_bytes: int = 8*1024*1024
    requests_per_second: float = 2.0
    total_budget: int = 100
    retries: int = 0
    methods: set[str] = field(default_factory=lambda: {'GET','HEAD'})
    journal_path: str | None = None
    per_host_requests_per_second: float | None = None
    max_concurrency: int = 4
    _count: int = 0
    _last: float = 0.0
    _host_last: dict[str, float] = field(default_factory=dict, repr=False)
    _lock: object = field(default_factory=threading.Lock, repr=False)
    _semaphore: object = field(default_factory=lambda: threading.BoundedSemaphore(4), repr=False)

    def __post_init__(self):
        if not self.assessment_id or not self.hosts: raise PolicyError('missing-assessment-or-scope')
        self.hosts={normalize_host(h) for h in self.hosts}
        if (self.timeout <= 0 or self.max_redirects < 0 or self.total_budget < 1
                or self.requests_per_second <= 0 or self.max_response_bytes < 1
                or self.max_concurrency < 1
                or (self.per_host_requests_per_second is not None and self.per_host_requests_per_second <= 0)):
            raise PolicyError('invalid-policy-limits')
        self._semaphore = threading.BoundedSemaphore(self.max_concurrency)

    def event(self, kind, url='', outcome='info', reason=''):
        if not self.journal_path: return
        p=Path(self.journal_path); p.parent.mkdir(parents=True,exist_ok=True)
        record={'timestamp':time.time(),'assessment_id':self.assessment_id,'event':kind,'url':redact_url(url),'outcome':outcome,'reason_code':reason}
        line=json.dumps(record,sort_keys=True)
        # append-only event record with a hash of this record; not an authenticity guarantee
        record['integrity_sha256']=hashlib.sha256(line.encode()).hexdigest()
        with p.open('a',encoding='utf-8') as f: f.write(json.dumps(record,sort_keys=True)+'\n')

    def check_dns(self, url):
        p=urlsplit(url); host=normalize_host(p.hostname or '')
        try: ip=ipaddress.ip_address(host)
        except ValueError:
            try: rows=socket.getaddrinfo(host,p.port or (443 if p.scheme=='https' else 80),type=socket.SOCK_STREAM)
            except OSError as e: raise PolicyError('dns-failure',url) from e
            ips={ipaddress.ip_address(row[4][0].split('%')[0]) for row in rows}
            if not ips: raise PolicyError('dns-empty',url)
        else: ips={ip}
        for ip in ips:
            if ip.is_loopback and not self.allow_loopback: raise PolicyError('loopback-address-blocked',url)
            if ip.is_link_local and not self.allow_link_local: raise PolicyError('link-local-address-blocked',url)
            if (ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_unspecified) and not self.allow_private: raise PolicyError('restricted-address-blocked',url)

class GuardedSession:
    """Requests adapter that validates every hop and caps decoded response bytes.

    DNS is checked immediately before each request, but Requests' normal adapter
    resolves again at connect time. This implementation therefore does NOT claim
    connection-pinned DNS-rebinding protection.
    """
    _SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "cookie2"}

    def __init__(self, policy: TransportPolicy, session=None):
        self.policy = policy
        self.session = session or requests.Session()
        self.session.verify = True

    def request(self, method, url, **kwargs):
        method = method.upper()
        if method not in self.policy.methods:
            raise PolicyError('method-not-allowed', url)
        current = url
        original_origin = None
        headers = dict(kwargs.pop("headers", {}) or {})
        timeout = kwargs.pop("timeout", self.policy.timeout)
        if isinstance(timeout, (int, float)):
            timeout = (timeout, timeout)
        elif not isinstance(timeout, tuple) or len(timeout) != 2 or min(timeout) <= 0:
            raise PolicyError("invalid-timeout", url)
        # The adapter owns redirects, streaming, TLS verification and timeouts.
        kwargs.pop("allow_redirects", None)
        kwargs.pop("stream", None)
        kwargs["stream"] = True
        kwargs["verify"] = True
        for hop in range(self.policy.max_redirects + 1):
            current = validate_url(current, self.policy.hosts, self.policy.schemes,
                                   self.policy.ports, allow_subdomains=False)
            self.policy.check_dns(current)
            p = urlsplit(current)
            origin = (p.scheme, normalize_host(p.hostname or ""), p.port or (443 if p.scheme == "https" else 80))
            if original_origin is None:
                original_origin = origin
            elif origin != original_origin:
                # Never forward caller- or session-level credentials across an origin change.
                headers = {k: v for k, v in headers.items() if k.lower() not in self._SENSITIVE_HEADERS}
                for key in list(getattr(self.session, "headers", {}).keys()):
                    if key.lower() in self._SENSITIVE_HEADERS:
                        self.session.headers.pop(key, None)
                cookie_jar = getattr(self.session, "cookies", None)
                if cookie_jar is not None:
                    cookie_jar.clear()
                kwargs.pop("auth", None)
            with self.policy._lock:
                if self.policy._count >= self.policy.total_budget:
                    self.policy.event('request-blocked', current, 'blocked', 'request-budget-exhausted')
                    raise PolicyError('request-budget-exhausted', current)
                now = time.monotonic()
                delay = 1 / self.policy.requests_per_second - (now - self.policy._last)
                host_rate = self.policy.per_host_requests_per_second or self.policy.requests_per_second
                hdelay = 1 / host_rate - (now - self.policy._host_last.get(origin[1], 0.0))
                delay = max(delay, hdelay)
                if delay > 0:
                    time.sleep(delay)
                now = time.monotonic()
                self.policy._last = now
                self.policy._host_last[origin[1]] = now
                self.policy._count += 1
            self.policy.event('request-attempted', current, 'allowed', 'scope-and-destination-validated')
            try:
                with self.policy._semaphore:
                    resp = self.session.request(method, current, timeout=timeout,
                                                allow_redirects=False, headers=headers, **kwargs)
                    # Count decoded bytes while streaming. iter_content applies requests' decoding.
                    body = bytearray()
                    try:
                        iterator = resp.iter_content(chunk_size=65536) if hasattr(resp, "iter_content") else [getattr(resp, "content", b"")]
                        for chunk in iterator:
                            if not chunk:
                                continue
                            if len(body) + len(chunk) > self.policy.max_response_bytes:
                                resp.close()
                                self.policy.event('request-blocked', current, 'blocked', 'response-size-limit')
                                raise PolicyError('response-size-limit', current)
                            body.extend(chunk)
                        # Keep normal requests.Response semantics for downstream callers.
                        if hasattr(resp, "_content"):
                            resp._content = bytes(body)
                            resp._content_consumed = True
                    except Exception:
                        resp.close()
                        raise
            except requests.RequestException as e:
                self.policy.event('transport-error', current, 'error', type(e).__name__)
                raise
            if getattr(resp, "is_redirect", False) or getattr(resp, "is_permanent_redirect", False):
                loc = resp.headers.get('Location')
                status = resp.status_code
                resp.close()
                if not loc:
                    raise PolicyError('redirect-without-location', current)
                if hop >= self.policy.max_redirects:
                    self.policy.event('redirect-blocked', current, 'blocked', 'redirect-limit')
                    raise PolicyError('redirect-limit', current)
                nxt = urljoin(current, loc)
                # Validate before the next send; next iteration rechecks DNS and scope.
                validate_url(nxt, self.policy.hosts, self.policy.schemes, self.policy.ports, allow_subdomains=False)
                self.policy.event('redirect-allowed', nxt, 'allowed', 'destination-in-scope')
                current = nxt
                if status == 303 or (status in (301, 302) and method == 'POST'):
                    method = 'GET'
                    kwargs.pop('data', None)
                    kwargs.pop('json', None)
                continue
            self.policy.event('request-completed', current, 'allowed', f'http-{resp.status_code}')
            return resp
        raise PolicyError('redirect-limit', current)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def head(self, url, **kwargs):
        return self.request('HEAD', url, **kwargs)

    def close(self):
        self.session.close()

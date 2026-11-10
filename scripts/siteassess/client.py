"""Scope-aware HTTP client with rate limiting and secret redaction.

This wraps requests.Session so every call is:
  * confined to an explicit allowlist of in-scope hosts,
  * rate limited (conservative default),
  * logged with redacted sensitive values.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

DEFAULT_UA = "siteassess/1.0 (authorized security assessment)"

# Patterns used to redact sensitive material before anything is printed or stored.
_REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}
_REDACT_PARAM_KEYS = re.compile(
    r"(pass(word)?|pwd|token|secret|api[_-]?key|auth|session|csrf|otp|code)", re.I
)


def redact_value(value: str) -> str:
    """Return a non-reversible placeholder for a sensitive value."""
    if value is None:
        return value
    s = str(value)
    if len(s) <= 4:
        return "****"
    return f"{s[:2]}…{s[-2:]} [REDACTED len={len(s)}]"


def redact_headers(headers) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        out[k] = redact_value(v) if k.lower() in _REDACT_HEADERS else v
    return out


def redact_form(data) -> dict:
    out = {}
    for k, v in (data or {}).items():
        out[k] = redact_value(v) if _REDACT_PARAM_KEYS.search(k or "") else v
    return out


@dataclass
class ScopeError(Exception):
    url: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"Refusing out-of-scope request: {self.url}"


@dataclass
class Client:
    """A rate-limited, scope-restricted HTTP session."""

    allowed_hosts: set[str]
    rate_limit_s: float = 1.0          # minimum seconds between requests
    timeout: float = 20.0
    user_agent: str = DEFAULT_UA
    verify_tls: bool = True
    log: list = field(default_factory=list)
    _last_request: float = 0.0
    session: requests.Session = field(default_factory=requests.Session)

    def __post_init__(self) -> None:
        self.allowed_hosts = {h.lower() for h in self.allowed_hosts}
        self.session.headers.update({"User-Agent": self.user_agent})

    def in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(host == h or host.endswith("." + h) for h in self.allowed_hosts)

    def _throttle(self) -> None:
        wait = self.rate_limit_s - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def request(self, method: str, url: str, *, allow_redirects: bool = True, **kw):
        if not self.in_scope(url):
            raise ScopeError(url)
        self._throttle()
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify_tls)
        resp = self.session.request(method, url, allow_redirects=allow_redirects, **kw)
        self.log.append(
            {
                "method": method,
                "url": url,
                "final_url": resp.url,
                "status": resp.status_code,
                "length": len(resp.content),
                "sent_data": redact_form(kw.get("data")),
            }
        )
        return resp

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw):
        return self.request("HEAD", url, **kw)

    def post(self, url: str, **kw):
        return self.request("POST", url, **kw)

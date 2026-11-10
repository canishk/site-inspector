"""Passive reconnaissance: security headers, TLS, cookies, tech fingerprint, robots/sitemap.

All checks here are low-impact GET/HEAD observations. Nothing is submitted or mutated.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from .client import Client, redact_value

# Security response headers we expect on a hardened app, with a short "why it matters".
SECURITY_HEADERS = {
    "strict-transport-security": "Forces HTTPS; mitigates downgrade/MITM.",
    "content-security-policy": "Primary defense against XSS / data injection.",
    "x-content-type-options": "Stops MIME sniffing (expect: nosniff).",
    "x-frame-options": "Legacy clickjacking defense (or CSP frame-ancestors).",
    "referrer-policy": "Limits referrer leakage of sensitive URLs.",
    "permissions-policy": "Restricts powerful browser features.",
    "cross-origin-opener-policy": "Isolates browsing context (Spectre class).",
    "cross-origin-resource-policy": "Controls cross-origin resource embedding.",
    "cross-origin-embedder-policy": "Required for cross-origin isolation.",
}

# Header -> technology fingerprint hints (confidence is reported, never asserted as exact).
FINGERPRINT_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via"]

COOKIE_FLAGS = ["secure", "httponly", "samesite"]


def tls_info(hostname: str, port: int = 443, timeout: float = 15.0) -> dict:
    """Fetch certificate metadata and negotiated protocol (read-only)."""
    info: dict = {"hostname": hostname, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                info["protocol"] = ssock.version()
                info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                cert = ssock.getpeercert()
        info["subject"] = dict(x[0] for x in cert.get("subject", []))
        info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter")
        info["not_after"] = not_after
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            info["days_to_expiry"] = (exp - datetime.now(timezone.utc)).days
        info["san"] = [v for (k, v) in cert.get("subjectAltName", [])]
        info["valid"] = True
    except Exception as e:
        info["valid"] = False
        info["error"] = str(e)
    return info


def analyze_headers(headers) -> dict:
    lower = {k.lower(): v for k, v in headers.items()}
    present, missing = {}, {}
    for h, why in SECURITY_HEADERS.items():
        if h in lower:
            present[h] = lower[h]
        else:
            missing[h] = why
    fingerprints = {h: lower[h] for h in FINGERPRINT_HEADERS if h in lower}
    return {"present": present, "missing": missing, "fingerprints": fingerprints}


def analyze_cookies(resp) -> list[dict]:
    """Report cookie security attributes without exposing values."""
    out = []
    for raw in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        out.append(
            {
                "name": name,
                "value": "[REDACTED]",
                "secure": "secure" in low,
                "httponly": "httponly" in low,
                "samesite": next(
                    (p.split("=", 1)[1].strip() for p in raw.split(";")
                     if p.strip().lower().startswith("samesite=")),
                    None,
                ),
            }
        )
    # Fallback via cookie jar if raw header list is unavailable.
    if not out:
        for c in resp.cookies:
            out.append(
                {
                    "name": c.name,
                    "value": "[REDACTED]",
                    "secure": c.secure,
                    "httponly": bool(c._rest.get("HttpOnly", False)),
                    "samesite": c._rest.get("SameSite"),
                }
            )
    return out


def check_redirect(client: Client, base_url: str) -> dict:
    """Does plain HTTP redirect to HTTPS?"""
    parsed = urlparse(base_url)
    http_url = f"http://{parsed.hostname}{parsed.path or '/'}"
    result = {"http_url": http_url}
    try:
        r = client.request("GET", http_url, allow_redirects=False)
        result["status"] = r.status_code
        loc = r.headers.get("Location", "")
        result["location"] = loc
        result["upgrades_to_https"] = loc.startswith("https://")
    except Exception as e:
        result["error"] = str(e)
    return result


def probe_paths(client: Client, base_url: str) -> list[dict]:
    """Check a small set of common informational paths (read-only, benign)."""
    candidates = [
        "robots.txt", "sitemap.xml", ".git/HEAD", ".env", "server-status",
        "phpinfo.php", "config.php.bak", "backup.zip", "readme.html",
        "wp-login.php", ".well-known/security.txt",
    ]
    results = []
    for path in candidates:
        url = urljoin(base_url.rstrip("/") + "/", path)
        try:
            r = client.get(url, allow_redirects=False)
            snippet = ""
            if r.status_code == 200 and "text" in r.headers.get("Content-Type", ""):
                snippet = r.text[:200].replace("\n", " ")
            results.append(
                {"path": path, "url": url, "status": r.status_code,
                 "length": len(r.content), "snippet": snippet}
            )
        except Exception as e:
            results.append({"path": path, "url": url, "error": str(e)})
    return results


def _json_shape(obj, depth: int = 0):
    """Describe JSON structure (keys and types) without exposing values."""
    if depth > 3:
        return "…"
    if isinstance(obj, dict):
        return {k: _json_shape(v, depth + 1) for k, v in list(obj.items())[:40]}
    if isinstance(obj, list):
        return [f"list[{len(obj)}]", _json_shape(obj[0], depth + 1)] if obj else ["list[0]"]
    return type(obj).__name__


def probe_endpoints(client: Client, base_url: str, paths: list[str],
                    test_origin: str = "https://evil.example") -> list[dict]:
    """Anonymous GET of each path; reports status, CORS behaviour and JSON shape only."""
    results = []
    for path in paths:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        headers = {"Origin": test_origin} if test_origin else {}
        try:
            r = client.get(url, allow_redirects=False, headers=headers)
        except Exception as e:
            results.append({"path": path, "error": str(e)})
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        entry = {
            "path": path,
            "status": r.status_code,
            "location": r.headers.get("Location"),
            "content_type": r.headers.get("Content-Type", ""),
            "length": len(r.content),
            "cache_control": r.headers.get("Cache-Control"),
            "acao": acao,
            "acac": r.headers.get("Access-Control-Allow-Credentials"),
            "cors_reflects_origin": bool(test_origin) and acao == test_origin,
            "set_cookie_names": [c.name for c in r.cookies],
        }
        if "json" in entry["content_type"]:
            try:
                entry["json_shape"] = _json_shape(r.json())
            except ValueError:
                pass
        results.append(entry)
    return results


def run(client: Client, base_url: str) -> dict:
    """Full passive recon pass for a base URL."""
    r = client.get(base_url)
    hostname = urlparse(r.url).hostname
    return {
        "base_url": base_url,
        "final_url": r.url,
        "status": r.status_code,
        "headers": analyze_headers(r.headers),
        "cookies": analyze_cookies(r),
        "tls": tls_info(hostname) if urlparse(r.url).scheme == "https" else {"valid": False, "error": "not https"},
        "https_redirect": check_redirect(client, base_url),
        "interesting_paths": probe_paths(client, base_url),
    }

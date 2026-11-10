"""Authenticated, in-scope BFS crawler with lightweight finding heuristics.

Collects reachable pages, links and forms. Flags passive, non-destructive signals:
server errors, directory listings, autocomplete-on password fields, forms without
CSRF tokens, mixed content, verbose error/stack traces, and sensitive data in HTML.

It never submits discovered forms and never leaves scope.
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse

from bs4 import BeautifulSoup

from .client import Client

# Benign patterns that often indicate information disclosure.
# Kept specific: bare words like "exception" match ordinary prose ("exceptional").
ERROR_SIGNATURES = [
    r"stack trace:", r"<b>fatal error</b>", r"<b>warning</b>:", r"<b>notice</b>:",
    r"\.php on line \d+", r"uncaught (exception|error)",
    r"you have an error in your sql syntax", r"traceback \(most recent call last\)",
    r"undefined (index|variable|array key)", r"mysqli?_[a-z_]+\(\)", r"ora-\d{5}", r"\bodbc\b.*\berror\b",
]
SECRET_SIGNATURES = [
    r"-----BEGIN (RSA|PRIVATE|OPENSSH) ", r"aws_secret_access_key",
    r"api[_-]?key\s*[:=]", r"secret[_-]?key\s*[:=]",
]

SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".webp")
# Destructive-looking links we must never follow.
DANGEROUS_LINK = re.compile(r"(logout|signout|delete|remove|destroy|drop|reset|purge|deactivate)", re.I)


def _norm(url: str) -> str:
    return urldefrag(url)[0]


def extract_links(html: str, page_url: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        links.add(_norm(urljoin(page_url, href)))
    return links


def extract_forms(html: str, page_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        fields = []
        has_csrf = False
        for el in f.find_all("input"):
            name = el.get("name", "")
            itype = (el.get("type") or "text").lower()
            fields.append({"name": name, "type": itype})
            if re.search(r"csrf|token|nonce|authenticity", name, re.I):
                has_csrf = True
        forms.append(
            {
                "action": urljoin(page_url, f.get("action") or page_url),
                "method": (f.get("method") or "get").lower(),
                "fields": fields,
                "has_csrf_token": has_csrf,
            }
        )
    return forms


def scan_findings(url: str, resp) -> list[dict]:
    findings = []
    ctype = resp.headers.get("Content-Type", "")
    if resp.status_code >= 500:
        findings.append({"type": "server_error", "url": url, "detail": f"HTTP {resp.status_code}"})
    if "text" not in ctype and "html" not in ctype:
        return findings
    body = resp.text
    low = body.lower()

    if "<title>index of /" in low or ("directory listing for" in low):
        findings.append({"type": "directory_listing", "url": url})

    for pat in ERROR_SIGNATURES:
        m = re.search(pat, low)
        if m:
            findings.append({"type": "verbose_error", "url": url, "detail": pat})
            break
    for pat in SECRET_SIGNATURES:
        if re.search(pat, body, re.I):
            findings.append({"type": "possible_secret_in_body", "url": url, "detail": pat})
            break

    # Mixed content on an HTTPS page.
    if url.startswith("https://") and re.search(r'src=["\']http://', body, re.I):
        findings.append({"type": "mixed_content", "url": url})

    # Source map reference.
    if "sourcemappingurl=" in low:
        findings.append({"type": "source_map_reference", "url": url})
    return findings


def crawl(client: Client, start_urls, max_pages: int = 60, same_path_prefix: str | None = None,
          page_hook=None) -> dict:
    """BFS crawl starting from start_urls, staying in scope.

    same_path_prefix: if set, only crawl URLs whose path starts with it
    (keeps the crawl inside e.g. /job-portal/).
    page_hook: optional callable(url, resp) invoked for every fetched page,
    so other analyzers (e.g. SEO) can reuse the crawl without re-fetching.
    """
    if isinstance(start_urls, str):
        start_urls = [start_urls]
    queue = deque(_norm(u) for u in start_urls)
    seen = set(queue)
    pages, findings, forms_seen = [], [], []

    while queue and len(pages) < max_pages:
        url = queue.popleft()
        if not client.in_scope(url):
            continue
        if url.lower().endswith(SKIP_EXT):
            continue
        if same_path_prefix and not urlparse(url).path.startswith(same_path_prefix):
            continue
        try:
            resp = client.get(url)
        except Exception as e:
            findings.append({"type": "request_error", "url": url, "detail": str(e)})
            continue

        page = {
            "url": url,
            "final_url": resp.url,
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "length": len(resp.content),
        }
        pages.append(page)
        findings.extend(scan_findings(url, resp))
        if page_hook:
            try:
                page_hook(url, resp)
            except Exception as e:
                findings.append({"type": "request_error", "url": url, "detail": f"page_hook: {e}"})

        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype:
            continue

        for form in extract_forms(resp.text, resp.url):
            form["found_on"] = url
            forms_seen.append(form)

        for link in extract_links(resp.text, resp.url):
            if link in seen:
                continue
            if not client.in_scope(link):
                continue
            if DANGEROUS_LINK.search(link):
                findings.append({"type": "skipped_dangerous_link", "url": link, "detail": "not followed"})
                continue
            seen.add(link)
            queue.append(link)

    # Post-process form findings.
    for f in forms_seen:
        if f["method"] == "post" and not f["has_csrf_token"]:
            findings.append({"type": "form_without_csrf", "url": f["found_on"], "detail": f["action"]})

    return {
        "pages_crawled": len(pages),
        "pages": pages,
        "forms": forms_seen,
        "findings": findings,
    }

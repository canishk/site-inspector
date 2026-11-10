"""Client-side (JavaScript bundle) reconnaissance for SPA / Next.js / React apps.

For each page, downloads the same-origin script bundles the browser would load and
looks for: framework markers, API endpoints, client-exposed config keys, backend
providers (Supabase, Firebase, ...), source maps, and app routes.

Read-only. Values that look like secrets are redacted before being returned.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .client import Client, redact_value

FRAMEWORK_MARKERS = {
    "Next.js": [r"/_next/static/", r"__NEXT_DATA__", r"self\.__next_f"],
    "React": [r"react-dom", r"__reactFiber", r"createElement\("],
    "Vue": [r"__vue__", r"createApp\("],
    "Angular": [r"ng-version", r"ɵcmp"],
    "Vite": [r"/assets/index-[\w-]+\.js", r"import\.meta\.env"],
}

PROVIDER_MARKERS = {
    "Supabase": r"https://[a-z0-9]{10,}\.supabase\.co",
    "Firebase": r"[a-z0-9-]+\.firebaseapp\.com|firebaseio\.com|apiKey:\s*\"AIza",
    "Clerk": r"clerk\.[a-z.]+|pk_(test|live)_[A-Za-z0-9]+",
    "Auth0": r"[a-z0-9-]+\.auth0\.com",
    "MongoDB Atlas": r"mongodb(\+srv)?://",
    "Stripe": r"pk_(test|live)_[A-Za-z0-9]{10,}",
    "Google Analytics": r"G-[A-Z0-9]{6,}|UA-\d+-\d+",
    "Sentry": r"ingest\.sentry\.io",
}

# Secret-ish values. Publishable/anon keys are expected client-side; flagged for review.
SECRET_PATTERNS = {
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "google_api_key": r"AIza[0-9A-Za-z_-]{35}",
    "stripe_secret": r"sk_(live|test)_[0-9A-Za-z]{10,}",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "mongodb_uri": r"mongodb(\+srv)?://[^\s\"'`]+",
    "generic_secret_assign": r"(?i)(secret|password|passwd|private_key)[\"']?\s*[:=]\s*[\"'][^\"']{6,}[\"']",
}

API_PATTERN = re.compile(r"[\"'`](/api/[A-Za-z0-9_\-/\[\].{}$]*)[\"'`]")
ABS_URL_PATTERN = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./]*)?")
ROUTE_PATTERN = re.compile(r"[\"'`](/(?:admin|dashboard|api|auth|login|account|settings|jobs?|users?)[A-Za-z0-9_\-/]*)[\"'`]")
ENV_PATTERN = re.compile(r"\b(NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+)\b")


def script_urls(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for s in soup.find_all("script", src=True):
        urls.append(urljoin(page_url, s["src"]))
    # Next.js preloads chunks via <link rel=preload as=script>
    for link in soup.find_all("link", href=True):
        if link.get("as") == "script" or (link.get("rel") and "modulepreload" in link.get("rel")):
            urls.append(urljoin(page_url, link["href"]))
    return list(dict.fromkeys(urls))


def analyze_text(text: str) -> dict:
    frameworks = [name for name, pats in FRAMEWORK_MARKERS.items()
                  if any(re.search(p, text) for p in pats)]
    providers = {}
    for name, pat in PROVIDER_MARKERS.items():
        m = re.search(pat, text)
        if m:
            providers[name] = m.group(0)[:80]
    secrets = []
    for kind, pat in SECRET_PATTERNS.items():
        for m in re.finditer(pat, text):
            secrets.append({"kind": kind, "value": redact_value(m.group(0))})
            if len(secrets) > 30:
                break
    return {
        "frameworks": frameworks,
        "providers": providers,
        "api_paths": sorted(set(API_PATTERN.findall(text))),
        "routes": sorted(set(ROUTE_PATTERN.findall(text))),
        "env_names": sorted(set(ENV_PATTERN.findall(text))),
        "external_hosts": sorted({urlparse(u).hostname for u in ABS_URL_PATTERN.findall(text)
                                  if urlparse(u).hostname}),
        "secrets": secrets,
        "source_map_ref": "sourceMappingURL=" in text,
    }


def run(client: Client, pages: list[str], max_scripts: int = 60) -> dict:
    merged: dict = {"pages": [], "scripts": [], "frameworks": set(), "providers": {},
                    "api_paths": set(), "routes": set(), "env_names": set(),
                    "external_hosts": set(), "secrets": [], "source_maps": []}
    seen_scripts: set[str] = set()

    def absorb(res: dict, where: str) -> None:
        merged["frameworks"].update(res["frameworks"])
        merged["providers"].update(res["providers"])
        merged["api_paths"].update(res["api_paths"])
        merged["routes"].update(res["routes"])
        merged["env_names"].update(res["env_names"])
        merged["external_hosts"].update(res["external_hosts"])
        for s in res["secrets"]:
            merged["secrets"].append({**s, "found_in": where})

    for page in pages:
        r = client.get(page)
        merged["pages"].append({"url": page, "status": r.status_code})
        absorb(analyze_text(r.text), page)
        for su in script_urls(r.text, r.url):
            if su in seen_scripts or len(seen_scripts) >= max_scripts or not client.in_scope(su):
                continue
            seen_scripts.add(su)
            try:
                sr = client.get(su)
            except Exception as e:
                merged["scripts"].append({"url": su, "error": str(e)})
                continue
            res = analyze_text(sr.text)
            absorb(res, su)
            merged["scripts"].append({"url": su, "status": sr.status_code, "length": len(sr.content)})
            if res["source_map_ref"] or sr.headers.get("SourceMap") or sr.headers.get("X-SourceMap"):
                map_url = su + ".map"
                try:
                    mr = client.head(map_url)
                    merged["source_maps"].append({"script": su, "map_url": map_url, "status": mr.status_code})
                except Exception:
                    pass

    for k in ("frameworks", "api_paths", "routes", "env_names", "external_hosts"):
        merged[k] = sorted(merged[k])
    return merged

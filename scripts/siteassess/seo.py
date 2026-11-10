"""SEO / crawlability checks (non-security).

These checks are about search-engine discoverability and on-page quality, NOT
security. They are reported in their own section so an SEO gap is never mistaken
for a vulnerability.

Usage patterns:
  * Per-page: `analyze_page(url, resp)` returns on-page SEO attributes.
  * Live crawl collection: feed each crawled page to `SeoCollector.feed`, then
    call `.summary()` for site-level aggregation (duplicates, coverage, issues).
  * Site-level: `site_checks(client, base_url)` inspects robots.txt / sitemap.xml.
  * Standalone: `run(client, base_url, max_pages)` crawls and returns a full report.

Recommended ranges (industry conventions, not hard rules):
  * <title>: ~30-60 characters
  * <meta description>: ~50-160 characters
  * exactly one <h1> per page
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .client import Client

TITLE_MIN, TITLE_MAX = 30, 60
DESC_MIN, DESC_MAX = 50, 160
THIN_CONTENT_WORDS = 200
SOFT_404 = re.compile(r"not found|does not exist|404|page unavailable", re.I)


def _text(el):
    return el.get_text(" ", strip=True) if el else None


def analyze_page(url: str, resp) -> dict:
    """Extract on-page SEO attributes from an HTML response."""
    ctype = resp.headers.get("Content-Type", "")
    if "html" not in ctype:
        return {"url": url, "html": False}

    soup = BeautifulSoup(resp.text, "html.parser")
    html_tag = soup.find("html")

    title = _text(soup.title)
    desc_tag = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    description = desc_tag.get("content", "").strip() if desc_tag else None

    robots_tag = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
    robots = (robots_tag.get("content", "") if robots_tag else "")
    xr = resp.headers.get("X-Robots-Tag", "")
    robots_all = f"{robots} {xr}".lower()

    canonical_tag = soup.find("link", attrs={"rel": re.compile(r"^canonical$", re.I)})
    canonical = canonical_tag.get("href") if canonical_tag else None

    h1s = [_text(h) for h in soup.find_all("h1")]
    imgs = soup.find_all("img")
    imgs_missing_alt = sum(1 for i in imgs if not (i.get("alt") or "").strip())

    og = {
        m.get("property", "").lower(): m.get("content", "")
        for m in soup.find_all("meta", property=re.compile(r"^og:", re.I))
    }
    twitter = soup.find("meta", attrs={"name": re.compile(r"^twitter:card$", re.I)})
    jsonld = soup.find_all("script", attrs={"type": re.compile(r"ld\+json", re.I)})
    hreflang = [
        l.get("hreflang") for l in soup.find_all("link", attrs={"rel": "alternate"})
        if l.get("hreflang")
    ]

    body_text = soup.get_text(" ", strip=True)
    word_count = len(body_text.split())

    return {
        "url": url,
        "html": True,
        "status": resp.status_code,
        "title": title,
        "title_len": len(title) if title else 0,
        "meta_description": description,
        "desc_len": len(description) if description else 0,
        "canonical": canonical,
        "meta_robots": robots_all.strip() or None,
        "noindex": "noindex" in robots_all,
        "nofollow": "nofollow" in robots_all,
        "h1_count": len(h1s),
        "lang": html_tag.get("lang") if html_tag else None,
        "has_viewport": bool(soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})),
        "charset": bool(soup.find("meta", charset=True)),
        "og_count": len(og),
        "og_image": "og:image" in og,
        "has_twitter_card": bool(twitter),
        "structured_data_count": len(jsonld),
        "img_total": len(imgs),
        "img_missing_alt": imgs_missing_alt,
        "word_count": word_count,
        "hreflang": hreflang,
    }


class SeoCollector:
    """Accumulates per-page SEO data during a crawl, then summarizes it."""

    def __init__(self) -> None:
        self.pages: list[dict] = []

    def feed(self, url: str, resp) -> None:
        data = analyze_page(url, resp)
        if data.get("html"):
            self.pages.append(data)

    def summary(self) -> dict:
        all_pages = self.pages
        n = len(all_pages)
        # On-page checks only make sense for pages that actually load.
        pages = [p for p in all_pages if p["status"] < 400]

        def dup_map(key):
            seen: dict = {}
            for p in pages:
                v = (p.get(key) or "").strip()
                if v:
                    seen.setdefault(v, []).append(p["url"])
            return {v: urls for v, urls in seen.items() if len(urls) > 1}

        issues = {
            "missing_title": [p["url"] for p in pages if not p["title"]],
            "title_length_off": [p["url"] for p in pages
                                 if p["title"] and not (TITLE_MIN <= p["title_len"] <= TITLE_MAX)],
            "duplicate_titles": dup_map("title"),
            "missing_description": [p["url"] for p in pages if not p["meta_description"]],
            "description_length_off": [p["url"] for p in pages
                                       if p["meta_description"] and not (DESC_MIN <= p["desc_len"] <= DESC_MAX)],
            "duplicate_descriptions": dup_map("meta_description"),
            "missing_h1": [p["url"] for p in pages if p["h1_count"] == 0],
            "multiple_h1": [p["url"] for p in pages if p["h1_count"] > 1],
            "missing_canonical": [p["url"] for p in pages if not p["canonical"]],
            "noindex_pages": [p["url"] for p in pages if p["noindex"]],
            "missing_viewport": [p["url"] for p in pages if not p["has_viewport"]],
            "missing_lang": [p["url"] for p in pages if not p["lang"]],
            "missing_og": [p["url"] for p in pages if p["og_count"] == 0],
            "no_structured_data": [p["url"] for p in pages if p["structured_data_count"] == 0],
            "images_missing_alt": [
                {"url": p["url"], "missing": p["img_missing_alt"], "total": p["img_total"]}
                for p in pages if p["img_missing_alt"] > 0
            ],
            "thin_content": [p["url"] for p in pages if p["word_count"] < THIN_CONTENT_WORDS],
            "broken_pages": [p["url"] for p in all_pages if p["status"] >= 400],
            "soft_404": [p["url"] for p in pages
                         if p["status"] == 200 and SOFT_404.search(p["title"] or "")],
        }
        return {"pages_analyzed": n, "issues": issues}


def site_checks(client: Client, base_url: str) -> dict:
    """Check robots.txt and sitemap.xml at the site root and under base path."""
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    out: dict = {}

    def probe(url):
        try:
            r = client.get(url, allow_redirects=True)
            is_xml_or_text = any(t in r.headers.get("Content-Type", "")
                                 for t in ("xml", "text/plain", "text"))
            return {
                "url": url,
                "status": r.status_code,
                "present": r.status_code == 200 and is_xml_or_text and len(r.content) < 2_000_000,
                "body": r.text if r.status_code == 200 and len(r.text) < 100_000 else "",
            }
        except Exception as e:
            return {"url": url, "error": str(e), "present": False}

    robots = probe(urljoin(root, "robots.txt"))
    has_sitemap_directive = bool(robots.get("body")) and "sitemap:" in robots["body"].lower()
    robots["declares_sitemap"] = has_sitemap_directive
    robots.pop("body", None)

    sitemap_root = probe(urljoin(root, "sitemap.xml"))
    sitemap_root.pop("body", None)
    sitemap_base = probe(urljoin(base_url.rstrip("/") + "/", "sitemap.xml"))
    sitemap_base.pop("body", None)

    out["robots_txt"] = robots
    out["sitemap_root"] = sitemap_root
    out["sitemap_base"] = sitemap_base
    out["sitemap_present"] = sitemap_root.get("present") or sitemap_base.get("present")
    return out


def run(client: Client, base_url: str, max_pages: int = 40) -> dict:
    """Standalone SEO pass: light crawl + per-page analysis + site checks."""
    from . import crawler  # local import to avoid a hard cycle

    collector = SeoCollector()
    crawl = crawler.crawl(
        client, base_url, max_pages=max_pages,
        same_path_prefix=urlparse(base_url).path or None,
        page_hook=collector.feed,
    )
    return {
        "base_url": base_url,
        "pages": collector.pages,
        "summary": collector.summary(),
        "site": site_checks(client, base_url),
        "pages_crawled": crawl["pages_crawled"],
    }

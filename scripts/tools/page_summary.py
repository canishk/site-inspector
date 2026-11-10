#!/usr/bin/env python3
"""Summarize what an anonymous visitor receives from a page, without dumping content.

Reports visible headings, link targets, form/field names, PII-pattern counts and
small API error bodies. Useful to decide whether a "200 OK" on a protected route is
a real access-control failure or just a client-side shell.

Usage: python tools/page_summary.py URL [URL ...]
"""
import re
import sys

import requests
from bs4 import BeautifulSoup

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"(?<!\d)\+?\d[\d -]{8,13}\d(?!\d)")


def summarize(url: str) -> None:
    r = requests.get(url, timeout=20, headers={"User-Agent": "siteassess/1.0"})
    print("=" * 70)
    print(f"{url} -> {r.status_code} {r.headers.get('Content-Type', '')} {len(r.content)}B")
    if "json" in r.headers.get("Content-Type", ""):
        body = r.text
        print("  json body:", body if len(body) <= 300 else body[:300] + " …")
        return
    soup = BeautifulSoup(r.text, "html.parser")
    for s in soup(["script", "style", "noscript"]):
        s.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ")).strip()
    print("  title    :", soup.title.string.strip() if soup.title and soup.title.string else None)
    print("  headings :", [h.get_text(" ", strip=True)[:60] for h in soup.find_all(["h1", "h2", "h3"])][:15])
    print("  links    :", sorted({a["href"] for a in soup.find_all("a", href=True)})[:25])
    print("  forms    :", [[i.get("name") or i.get("type") for i in f.find_all("input")] for f in soup.find_all("form")])
    print(f"  visible text: {len(text.split())} words; emails={len(set(EMAIL.findall(text)))} "
          f"phone-like={len(set(PHONE.findall(text)))}")
    print("  text sample :", text[:400])
    raw = r.text
    print("  markers  : loading/redirect/unauth ->",
          [m for m in ("Loading", "Unauthorized", "Sign in", "Login", "redirect", "NEXT_REDIRECT") if m in raw])


if __name__ == "__main__":
    for u in sys.argv[1:]:
        summarize(u)

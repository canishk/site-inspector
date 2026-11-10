"""Render a Markdown assessment report from collected results."""
from __future__ import annotations

from datetime import datetime

# Map crawler finding types -> (severity, OWASP-ish category, remediation).
FINDING_META = {
    "server_error": ("Low", "Information Disclosure", "Return generic error pages; log details server-side only."),
    "directory_listing": ("Medium", "Security Misconfiguration", "Disable automatic directory indexing."),
    "verbose_error": ("Medium", "Information Disclosure", "Disable debug output; show generic errors in production."),
    "possible_secret_in_body": ("High", "Sensitive Data Exposure", "Remove secrets from responses; rotate if real."),
    "mixed_content": ("Low", "Transport Security", "Load all sub-resources over HTTPS."),
    "source_map_reference": ("Low", "Information Disclosure", "Do not ship source maps to production."),
    "form_without_csrf": ("Medium", "CSRF", "Add per-session anti-CSRF tokens to state-changing forms."),
    "password_autocomplete_on": ("Informational", "Client-side Hardening", "Consider autocomplete handling per policy."),
    "request_error": ("Informational", "Availability", "Review endpoint; may be transient."),
    "skipped_dangerous_link": ("Informational", "Scan Note", "Link intentionally not followed (safety)."),
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _header_scorecard(recon: dict) -> list[str]:
    lines = ["| Control | Status | Notes |", "|---|---|---|"]
    h = recon.get("headers", {})
    present, missing = h.get("present", {}), h.get("missing", {})
    for name in sorted(set(present) | set(missing)):
        if name in present:
            lines.append(f"| `{name}` | Pass | present |")
        else:
            lines.append(f"| `{name}` | Needs Improvement | {missing[name]} |")
    return lines


def _cookie_table(recon: dict) -> list[str]:
    cookies = recon.get("cookies", [])
    if not cookies:
        return ["_No cookies observed on the initial response._"]
    lines = ["| Cookie | Secure | HttpOnly | SameSite |", "|---|---|---|---|"]
    for c in cookies:
        lines.append(f"| `{c['name']}` | {c['secure']} | {c['httponly']} | {c['samesite']} |")
    return lines


def _aggregate_findings(crawl: dict) -> list[dict]:
    agg: dict = {}
    for f in crawl.get("findings", []):
        sev, cat, fix = FINDING_META.get(f["type"], ("Informational", "Other", "Review."))
        key = f["type"]
        agg.setdefault(key, {"type": key, "severity": sev, "category": cat,
                             "remediation": fix, "instances": []})
        agg[key]["instances"].append({"url": f.get("url"), "detail": f.get("detail")})
    return sorted(agg.values(), key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))


# SEO issue -> (priority, why it matters / fix). Priority is SEO impact, NOT security.
SEO_META = {
    "missing_title": ("High", "Every page needs a unique <title>; it's the primary SERP label."),
    "title_length_off": ("Low", "Keep titles ~30-60 chars so they aren't truncated in results."),
    "duplicate_titles": ("Medium", "Duplicate titles dilute relevance; make each page's title unique."),
    "missing_description": ("Medium", "Add a meta description to control the SERP snippet."),
    "description_length_off": ("Low", "Keep descriptions ~50-160 chars."),
    "duplicate_descriptions": ("Low", "Write unique descriptions per page."),
    "missing_h1": ("Medium", "Add one descriptive <h1> per page."),
    "multiple_h1": ("Low", "Prefer a single <h1> for a clear topical signal."),
    "missing_canonical": ("Medium", "Add rel=canonical to consolidate duplicate URLs."),
    "noindex_pages": ("High", "Confirm these pages are intentionally excluded from search."),
    "missing_viewport": ("Medium", "Add a responsive viewport meta for mobile ranking."),
    "missing_lang": ("Low", "Set <html lang> for language targeting/accessibility."),
    "missing_og": ("Low", "Add Open Graph tags for richer social sharing."),
    "no_structured_data": ("Low", "Consider JSON-LD structured data (e.g. Organization, Article, JobPosting) for rich results."),
    "images_missing_alt": ("Low", "Add descriptive alt text for image SEO and accessibility."),
    "thin_content": ("Low", "Pages under ~200 words may be seen as thin content."),
    "broken_pages": ("High", "Fix or remove internal links that return 4xx/5xx (check for hrefs missing https://)."),
    "soft_404": ("Medium", "'Not found' pages returning 200 should return a real 404 status."),
}
SEO_PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _seo_section(seo: dict | None) -> list[str]:
    L = ["## J. SEO & Crawlability (non-security)", ""]
    if not seo:
        L.append("_Not performed._")
        L.append("")
        return L

    summary = seo.get("summary", {})
    issues = summary.get("issues", {})
    site = seo.get("site", {})

    L.append(f"- **Pages analyzed:** {summary.get('pages_analyzed', 0)}")
    robots = site.get("robots_txt", {})
    L.append(f"- **robots.txt:** {'present' if robots.get('present') else 'missing'} "
             f"(status {robots.get('status')}, declares sitemap: {robots.get('declares_sitemap')})")
    L.append(f"- **sitemap.xml:** {'present' if site.get('sitemap_present') else 'missing'}")
    L.append("")
    L.append("> SEO issues below affect search visibility, not security. Priority reflects SEO impact.")
    L.append("")

    # Order issues by SEO priority.
    rows = []
    for key, val in issues.items():
        if isinstance(val, dict):
            count = sum(len(urls) for urls in val.values())
        else:
            count = len(val) if isinstance(val, list) else 0
        if not count:
            continue
        prio, why = SEO_META.get(key, ("Low", ""))
        rows.append((SEO_PRIORITY_ORDER.get(prio, 9), prio, key, count, why, val))
    rows.sort(key=lambda r: r[0])

    if not rows:
        L.append("_No SEO issues detected in the analyzed pages._")
        L.append("")
        return L

    L.append("| Priority | Issue | Pages affected | Recommendation |")
    L.append("|---|---|---|---|")
    for _, prio, key, count, why, _val in rows:
        L.append(f"| {prio} | {key.replace('_',' ').title()} | {count} | {why} |")
    L.append("")

    # Show a few example URLs for the most impactful issues.
    for _, prio, key, count, _why, val in rows:
        if prio == "Low":
            continue
        L.append(f"**{key.replace('_',' ').title()}** ({count}):")
        if isinstance(val, dict):
            for v, urls in list(val.items())[:3]:
                L.append(f"- \"{v[:60]}\" → {len(urls)} pages")
        else:
            for item in val[:5]:
                u = item["url"] if isinstance(item, dict) else item
                L.append(f"- `{u}`")
        L.append("")
    return L


def build(engagement: dict, recon: dict, login_result: dict | None, crawl: dict,
          seo: dict | None = None) -> str:
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    findings = _aggregate_findings(crawl)
    counts: dict = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    L: list[str] = []
    L.append(f"# Web Application Security Assessment — {engagement.get('name','Target')}")
    L.append("")
    L.append("## A. Executive Summary")
    L.append("")
    L.append(f"- **Target:** {engagement.get('target')}")
    L.append(f"- **Authorization:** {engagement.get('authorization','client-authorized')}")
    L.append(f"- **Environment:** {engagement.get('environment','production')}")
    L.append(f"- **Assessment date:** {now}")
    L.append(f"- **Depth:** {engagement.get('depth','passive + authenticated + safe active')}")
    sev_line = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0],9))) or "none"
    L.append(f"- **Findings by severity:** {sev_line}")
    L.append(f"- **Pages crawled:** {crawl.get('pages_crawled',0)}")
    L.append("")
    L.append("> Non-destructive assessment. Findings below are leads validated by passive "
             "observation; items marked Likely need confirmation against source/config.")
    L.append("")

    # Tech fingerprint
    L.append("## B. Technology Fingerprint")
    L.append("")
    L.append("| Signal | Value | Confidence |")
    L.append("|---|---|---|")
    fp = recon.get("headers", {}).get("fingerprints", {})
    if fp:
        for k, v in fp.items():
            L.append(f"| `{k}` header | {v} | Medium |")
    else:
        L.append("| server headers | (none disclosed) | — |")
    L.append("")

    # TLS
    tls = recon.get("tls", {})
    L.append("## C. Transport / TLS")
    L.append("")
    if tls.get("valid"):
        L.append(f"- Protocol: `{tls.get('protocol')}`, cipher: `{tls.get('cipher')}`")
        L.append(f"- Certificate issuer: `{tls.get('issuer',{}).get('organizationName','?')}`")
        L.append(f"- Days to expiry: **{tls.get('days_to_expiry','?')}**")
    else:
        L.append(f"- TLS not validated: {tls.get('error')}")
    red = recon.get("https_redirect", {})
    L.append(f"- HTTP→HTTPS upgrade: **{red.get('upgrades_to_https')}** (status {red.get('status')})")
    L.append("")

    # Security headers scorecard
    L.append("## D. Security Header Scorecard")
    L.append("")
    L.extend(_header_scorecard(recon))
    L.append("")

    # Cookies
    L.append("## E. Cookies")
    L.append("")
    L.extend(_cookie_table(recon))
    L.append("")

    # Interesting paths
    L.append("## F. Exposed / Probed Paths")
    L.append("")
    L.append("| Path | Status | Length |")
    L.append("|---|---|---|")
    for p in recon.get("interesting_paths", []):
        if "error" in p:
            continue
        flag = " ⚠️" if p.get("status") == 200 else ""
        L.append(f"| `{p['path']}` | {p['status']}{flag} | {p.get('length','')} |")
    L.append("")

    # Auth
    L.append("## G. Authentication Check")
    L.append("")
    if login_result:
        L.append(f"- Login form detected: **{login_result.get('form_detected')}**")
        if login_result.get("form_detected"):
            L.append(f"- Submission endpoint: `{login_result.get('action')}`")
            L.append(f"- Hidden/anti-CSRF fields present: {login_result.get('hidden_fields')}")
            L.append(f"- Authenticated session likely: **{login_result.get('authenticated_likely')}** "
                     f"(status {login_result.get('post_status')}, cookie set: {login_result.get('set_cookie')})")
    else:
        L.append("- Not performed.")
    L.append("")

    # Findings register
    L.append("## H. Findings Register")
    L.append("")
    if not findings:
        L.append("_No heuristic findings from the crawl. Absence of findings is not proof of security._")
    for i, f in enumerate(findings, 1):
        L.append(f"### H{i}. {f['type'].replace('_',' ').title()} — {f['severity']}")
        L.append(f"- **Category:** {f['category']}")
        L.append(f"- **Instances:** {len(f['instances'])}")
        for inst in f["instances"][:8]:
            detail = f" ({inst['detail']})" if inst.get("detail") else ""
            L.append(f"  - `{inst['url']}`{detail}")
        if len(f["instances"]) > 8:
            L.append(f"  - … and {len(f['instances'])-8} more")
        L.append(f"- **Remediation:** {f['remediation']}")
        L.append("")

    # Coverage
    L.append("## I. Coverage & Limitations")
    L.append("")
    L.append("- **Performed:** passive recon, security headers, TLS, cookies, common-path probe, "
             "authenticated form login, in-scope authenticated crawl, passive finding heuristics"
             + (", anonymous SEO/crawlability pass." if seo else "."))
    L.append("- **Not performed:** exploitation, brute force / credential attacks, destructive actions, "
             "fuzzing, intrusive scanning, out-of-scope hosts.")
    L.append("- Heuristic findings are leads; confirm against application source and configuration.")
    L.append("")

    L.extend(_seo_section(seo))
    return "\n".join(L)


def build_platform_report(bundle: dict, out_dir: str = "") -> str:
    """Unified report from orchestrator bundle (merged findings + tool coverage)."""
    from .findings import SEVERITY_ORDER

    engagement = bundle.get("engagement", {})
    findings = bundle.get("findings", [])
    coverage = bundle.get("coverage", [])
    recon = bundle.get("recon") or {}
    crawl = bundle.get("crawl") or {"pages_crawled": 0}
    seo = bundle.get("seo")

    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    L: list[str] = []
    L.append(f"# Platform Security Assessment — {engagement.get('name', 'Target')}")
    L.append("")
    L.append("## A. Executive Summary")
    L.append("")
    L.append(f"- **Target:** {engagement.get('target')}")
    L.append(f"- **Profile:** `{engagement.get('profile', 'passive')}`")
    L.append(f"- **Authorization:** {engagement.get('authorization_note', 'pending')}")
    L.append(f"- **Authorized flag:** {engagement.get('authorized', False)}")
    L.append(f"- **Assessment date:** {now}")
    if out_dir:
        L.append(f"- **Artifacts:** `{out_dir}`")

    by_sev: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "Informational")] = by_sev.get(f.get("severity", "Informational"), 0) + 1
        src = f.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
    sev_line = ", ".join(
        f"{k}: {v}" for k, v in sorted(by_sev.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
    ) or "none"
    L.append(f"- **Merged findings by severity:** {sev_line}")
    L.append(f"- **Findings by source:** {', '.join(f'{k}={v}' for k, v in sorted(by_source.items())) or 'none'}")
    L.append(f"- **Pages crawled:** {crawl.get('pages_crawled', 0)}")
    L.append("")
    L.append("> Findings are normalized from native checks and external scanners. "
             "Confirm critical items against source and configuration.")
    L.append("")

    # Tool coverage
    L.append("## B. Tool Coverage")
    L.append("")
    L.append("| Stage | Status | Detail | Raw |")
    L.append("|---|---|---|---|")
    for c in coverage:
        raw = c.get("raw_ref") or c.get("raw_path") or ""
        L.append(f"| {c.get('name','?')} | {c.get('status','?')} | {c.get('detail','')[:80]} | `{raw}` |")
    L.append("")

    # Scorecard from recon if present
    if recon:
        L.append("## C. Security Header Scorecard")
        L.append("")
        L.extend(_header_scorecard(recon))
        L.append("")
        L.append("## D. Transport / TLS (native)")
        L.append("")
        tls = recon.get("tls", {})
        if tls.get("valid"):
            L.append(f"- Protocol: `{tls.get('protocol')}`, cipher: `{tls.get('cipher')}`")
            L.append(f"- Days to cert expiry: **{tls.get('days_to_expiry', '?')}**")
        else:
            L.append(f"- {tls.get('error', 'not validated')}")
        L.append("")

    L.append("## E. Merged Findings Register")
    L.append("")
    if not findings:
        L.append("_No findings recorded. Tools may have been skipped (Docker/browser unavailable)._")
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "Informational"), 9), f.get("title", "")),
    )
    for i, f in enumerate(sorted_findings[:80], 1):
        L.append(f"### E{i}. [{f.get('source')}] {f.get('title')} — **{f.get('severity')}** "
                 f"({f.get('confidence', 'Medium')} confidence)")
        L.append(f"- **OWASP / category:** {f.get('owasp_category', '')}")
        if f.get("url"):
            L.append(f"- **URL:** `{f['url']}`")
        if f.get("evidence"):
            L.append(f"- **Evidence:** {f['evidence'][:300]}")
        L.append(f"- **Remediation:** {f.get('remediation', '')[:400]}")
        if f.get("raw_ref"):
            L.append(f"- **Raw:** `{f['raw_ref']}`")
        L.append("")
    if len(sorted_findings) > 80:
        L.append(f"_… and {len(sorted_findings) - 80} more (see findings.json)._")
        L.append("")

    L.append("## F. Raw Artifacts")
    L.append("")
    L.append("- `findings.json` — merged normalized findings")
    L.append("- `coverage.json` — stage status")
    L.append("- `raw/` — scanner outputs (zap, nmap, testssl, browser)")
    L.append("- `recon.json`, `crawl.json`, `seo.json`, `js.json`, `login.json`, `request_log.json`")
    L.append("")

    L.append("## G. Limitations")
    L.append("")
    L.append("- Passive profile skips intrusive port scan and ZAP active scan unless `--authorized` and enabled.")
    L.append("- Docker/images must be present locally; missing Docker → tools marked skipped.")
    L.append("- Credentials never stored in artifacts; browser storageState deleted after run when possible.")
    L.append("")

    if seo:
        L.extend(_seo_section(seo))

    return "\n".join(L)

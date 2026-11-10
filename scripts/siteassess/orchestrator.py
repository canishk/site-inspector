"""Scan pipeline: native modules + external tools → merged findings."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from . import auth, crawler, jsrecon, recon, report, seo
from .client import Client
from .engagement import Engagement
from .findings import (
    Finding,
    StageCoverage,
    findings_to_json,
    from_crawl,
    from_recon_headers,
    merge,
)
from .tools import browser, nmap, testssl, zap


def _client(engagement: Engagement) -> Client:
    assert engagement.scope
    return Client(
        allowed_hosts=engagement.scope.allowed_hosts,
        rate_limit_s=engagement.scope.rate_limit_s,
        timeout=engagement.scope.request_timeout,
    )


def run_scan(
    engagement: Engagement,
    out_dir: Path,
    *,
    login_url: str | None = None,
    credentials: tuple[str, str] | None = None,
    auth_mode: str = "auto",
    user_field: str | None = None,
    callback_url: str | None = None,
    crawl_starts: list[str] | None = None,
    max_pages: int = 60,
    seo_max_pages: int = 40,
    zap_proxy: str | None = None,
) -> dict[str, Any]:
    """Execute all enabled stages; write artifacts and return bundle for reporting."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "raw").mkdir(exist_ok=True)
    target = engagement.target
    client = _client(engagement)
    coverage: list[StageCoverage] = []
    all_findings: list[Finding] = []
    bundle: dict[str, Any] = {
        "engagement": asdict(engagement),
        "timestamp": datetime.now().astimezone().isoformat(),
        "recon": None,
        "crawl": None,
        "seo": None,
        "jsrecon": None,
        "login": None,
    }

    # --- Native recon ---
    if engagement.use_native:
        try:
            rec = recon.run(client, target)
            bundle["recon"] = rec
            (out_dir / "recon.json").write_text(json.dumps(rec, indent=2, default=str), encoding="utf-8")
            all_findings.extend(from_recon_headers(rec))
            coverage.append(StageCoverage("native-recon", "ran", "headers/tls/paths"))
        except Exception as e:
            coverage.append(StageCoverage("native-recon", "failed", str(e)[:200]))

    # --- JS recon ---
    if engagement.use_native:
        try:
            pages = [target]
            if login_url:
                pages.append(login_url)
            js = jsrecon.run(client, pages)
            bundle["jsrecon"] = js
            (out_dir / "js.json").write_text(json.dumps(js, indent=2, default=str), encoding="utf-8")
            if js.get("secrets"):
                for s in js["secrets"][:10]:
                    all_findings.append(
                        Finding(
                            id=f"js-{s.get('kind','secret')}",
                            source="jsrecon",
                            severity="High",
                            confidence="Medium",
                            title=f"Possible secret in bundle: {s.get('kind')}",
                            owasp_category="Sensitive Data Exposure",
                            url=s.get("found_in", target),
                            evidence=s.get("value", "[redacted]"),
                            remediation="Remove secrets from client bundles; rotate if real.",
                            raw_ref="js.json",
                        )
                    )
            coverage.append(StageCoverage("jsrecon", "ran", f"scripts={len(js.get('scripts', []))}"))
        except Exception as e:
            coverage.append(StageCoverage("jsrecon", "failed", str(e)[:200]))

    # --- SEO ---
    if engagement.use_native:
        try:
            seo_result = seo.run(client, target, max_pages=seo_max_pages)
            bundle["seo"] = seo_result
            (out_dir / "seo.json").write_text(json.dumps(seo_result, indent=2, default=str), encoding="utf-8")
            coverage.append(StageCoverage("seo", "ran", f"pages={seo_result['summary']['pages_analyzed']}"))
        except Exception as e:
            coverage.append(StageCoverage("seo", "failed", str(e)[:200]))
            bundle["seo"] = None

    # --- Login (in-memory creds only) ---
    login_result = None
    if login_url and credentials:
        try:
            login_result = auth.login(
                client,
                login_url,
                credentials[0],
                credentials[1],
                mode=auth_mode,
                user_field=user_field,
                callback_url=callback_url,
            )
            bundle["login"] = login_result
            (out_dir / "login.json").write_text(json.dumps(login_result, indent=2), encoding="utf-8")
            st = "ran" if login_result.get("authenticated_likely") else "failed"
            coverage.append(StageCoverage("auth", st, f"mode={login_result.get('mode')}"))
        except Exception as e:
            coverage.append(StageCoverage("auth", "failed", str(e)[:200]))

    # --- Crawl ---
    if engagement.use_native:
        try:
            starts = [target]
            if login_url:
                fu = login_result.get("final_url", login_url) if login_result else login_url
                starts.append(fu)
            for s in crawl_starts or []:
                starts.append(urljoin(target, s))
            crawl = crawler.crawl(
                client,
                starts,
                max_pages=max_pages,
                same_path_prefix=engagement.scope.path_prefix if engagement.scope else None,
            )
            bundle["crawl"] = crawl
            (out_dir / "crawl.json").write_text(json.dumps(crawl, indent=2, default=str), encoding="utf-8")
            all_findings.extend(from_crawl(crawl))
            coverage.append(StageCoverage("crawl", "ran", f"pages={crawl['pages_crawled']}"))
        except Exception as e:
            coverage.append(StageCoverage("crawl", "failed", str(e)[:200]))
            bundle["crawl"] = {"pages_crawled": 0, "findings": []}

    (out_dir / "request_log.json").write_text(
        json.dumps(client.log, indent=2, default=str), encoding="utf-8"
    )

    # --- testssl ---
    if engagement.use_testssl:
        try:
            f, cov = testssl.run(out_dir, target_url=target)
            all_findings.extend(f)
            coverage.append(cov)
        except Exception as e:
            coverage.append(StageCoverage("testssl", "failed", str(e)[:200]))

    # --- nmap ---
    if engagement.use_nmap:
        if not engagement.authorized:
            coverage.append(StageCoverage("nmap", "skipped", "requires --authorized"))
        else:
            try:
                f, cov = nmap.run(engagement, out_dir, target_url=target)
                all_findings.extend(f)
                coverage.append(cov)
            except PermissionError as e:
                coverage.append(StageCoverage("nmap", "skipped", str(e)))
            except Exception as e:
                coverage.append(StageCoverage("nmap", "failed", str(e)[:200]))

    # --- ZAP ---
    if engagement.use_zap:
        mode = engagement.zap_mode or "baseline"
        if mode == "full" and not engagement.authorized:
            coverage.append(StageCoverage("zap", "skipped", "full scan requires --authorized"))
        else:
            try:
                f, cov = zap.run(engagement, out_dir, target_url=target, mode=mode)
                all_findings.extend(f)
                coverage.append(cov)
            except PermissionError as e:
                coverage.append(StageCoverage("zap", "skipped", str(e)))
            except Exception as e:
                coverage.append(StageCoverage("zap", "failed", str(e)[:200]))

    # --- Browser ---
    if engagement.use_browser:
        pages = []
        if bundle.get("crawl"):
            pages = [p["url"] for p in bundle["crawl"].get("pages", [])[:8]]
        if login_url:
            pages.insert(0, login_url)
        try:
            f, cov, _meta = browser.run_checks(
                out_dir,
                base_url=target,
                pages=pages,
                login_url=login_url,
                credentials=credentials,
                user_field=user_field or "email",
                proxy_server=zap_proxy,
            )
            all_findings.extend(f)
            coverage.append(cov)
        except Exception as e:
            coverage.append(StageCoverage("browser", "failed", str(e)[:200]))

    merged = merge(all_findings)
    (out_dir / "findings.json").write_text(
        json.dumps(findings_to_json(merged), indent=2), encoding="utf-8"
    )
    cov_dicts = [asdict(c) for c in coverage]
    (out_dir / "coverage.json").write_text(json.dumps(cov_dicts, indent=2), encoding="utf-8")

    bundle["findings"] = findings_to_json(merged)
    bundle["coverage"] = cov_dicts
    return bundle

"""Playwright browser automation: login, session export, lightweight DOM checks."""
from __future__ import annotations

import json
from pathlib import Path

from ..findings import Finding, StageCoverage, from_browser_checks

STORAGE_STATE = "browser_storage_state.json"


def _playwright_missing() -> str | None:
    try:
        import playwright  # noqa: F401
        return None
    except ImportError:
        return "playwright not installed (pip install playwright && playwright install chromium)"


def run_checks(
    out_dir: Path,
    *,
    base_url: str,
    pages: list[str],
    login_url: str | None = None,
    credentials: tuple[str, str] | None = None,
    user_field: str = "email",
    pass_field: str = "password",
    proxy_server: str | None = None,
    cleanup_state: bool = True,
) -> tuple[list[Finding], StageCoverage, dict]:
    """
    credentials: (username, password) held only in memory for this call.
  Never written to disk except cookies in storageState (deleted if cleanup_state).
    """
    miss = _playwright_missing()
    if miss:
        return [], StageCoverage("browser", "skipped", miss), {}

    from playwright.sync_api import sync_playwright

    raw = out_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    state_path = raw / STORAGE_STATE
    checks: list[dict] = []
    meta: dict = {"pages_visited": []}

    launch_opts: dict = {"headless": True}
    if proxy_server:
        launch_opts["proxy"] = {"server": proxy_server}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_opts)
            context = browser.new_context(ignore_https_errors=False)
            page = context.new_page()
            console_errors: list[str] = []

            def on_console(msg):
                if msg.type == "error":
                    console_errors.append(msg.text[:200])

            page.on("console", on_console)

            if login_url and credentials:
                page.goto(login_url, wait_until="networkidle", timeout=45000)
                # Try Auth.js-style form fields by common selectors.
                user, pwd = credentials
                filled = False
                for sel_u in (f"input[name='{user_field}']", "input[type='email']", "input[name='email']"):
                    if page.locator(sel_u).count():
                        page.fill(sel_u, user)
                        filled = True
                        break
                for sel_p in (f"input[name='{pass_field}']", "input[type='password']"):
                    if page.locator(sel_p).count():
                        page.fill(sel_p, pwd)
                        break
                if filled:
                    for sel in ("button[type='submit']", "input[type='submit']", "text=Sign in", "text=Log in"):
                        if page.locator(sel).count():
                            page.locator(sel).first.click()
                            page.wait_for_load_state("networkidle", timeout=30000)
                            break
                context.storage_state(path=str(state_path))
                meta["login_attempted"] = True

            visit = list(dict.fromkeys([base_url] + pages))[:15]
            for url in visit:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=45000)
                    meta["pages_visited"].append(url)
                    title = page.title()
                    mixed = page.evaluate(
                        """() => [...document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]')].length"""
                    )
                    if mixed and url.startswith("https://"):
                        checks.append({
                            "title": "Mixed content (HTTP sub-resources on HTTPS page)",
                            "severity": "Low",
                            "confidence": "High",
                            "category": "Transport Security",
                            "url": url,
                            "evidence": f"{mixed} insecure references",
                            "remediation": "Load all sub-resources over HTTPS.",
                        })
                    # DOM XSS sink heuristic (read-only).
                    sinks = page.evaluate(
                        """() => {
                        const html = document.documentElement.innerHTML;
                        const hits = [];
                        if (/innerHTML\\s*=/.test(html)) hits.push('innerHTML assignment');
                        if (document.querySelector('[onclick*="eval"]')) hits.push('onclick eval');
                        return hits;
                    }"""
                    )
                    for s in sinks or []:
                        checks.append({
                            "title": f"Potential DOM XSS sink: {s}",
                            "severity": "Medium",
                            "confidence": "Low",
                            "category": "Injection",
                            "url": url,
                            "evidence": s,
                            "remediation": "Avoid dangerous sinks; enforce CSP.",
                        })
                except Exception as e:
                    checks.append({
                        "title": "Page load error",
                        "severity": "Informational",
                        "confidence": "High",
                        "category": "Availability",
                        "url": url,
                        "evidence": str(e)[:200],
                        "remediation": "Review page availability.",
                    })

            for err in console_errors[:5]:
                checks.append({
                    "title": "Browser console error",
                    "severity": "Low",
                    "confidence": "Medium",
                    "category": "Information Disclosure",
                    "url": base_url,
                    "evidence": err,
                    "remediation": "Fix client-side errors; avoid leaking details in console.",
                })

            browser.close()
    except Exception as e:
        return [], StageCoverage("browser", "failed", str(e)[:300]), meta

    if cleanup_state and state_path.exists():
        try:
            state_path.unlink()
            meta["storage_state_deleted"] = True
        except OSError:
            meta["storage_state_deleted"] = False

    out_checks = raw / "browser_checks.json"
    out_checks.write_text(json.dumps(checks, indent=2), encoding="utf-8")
    findings = from_browser_checks(checks, raw_ref="raw/browser_checks.json")
    return findings, StageCoverage(
        "browser", "ran", f"visited={len(meta.get('pages_visited', []))}", raw_path="raw/browser_checks.json"
    ), meta

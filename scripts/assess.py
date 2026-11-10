#!/usr/bin/env python3
"""
assess.py - general-purpose, non-destructive web application assessment CLI.

Reusable against ANY authorized target. Nothing is hardcoded to a specific site.

Examples
--------
  # Full assessment (recon + login + authenticated crawl + report):
  python assess.py full --base https://example.com/app/ --login https://example.com/app/admin

  # Passive recon only (no credentials needed):
  python assess.py recon --base https://example.com/

  # Restrict crawl to a path prefix and cap pages:
  python assess.py full --base https://example.com/app/ --login https://example.com/app/admin \
       --path-prefix /app/ --max-pages 80

Credentials
-----------
  Never stored on disk. Supplied at runtime via:
    * interactive hidden prompt (default), or
    * environment variables ASSESS_USER / ASSESS_PASS (use --env-creds).

Safety
------
  Scope is restricted to the host of --base (plus any --allow-host). Conservative
  rate limiting. GET/HEAD only, except the single authenticated login POST.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

# Allow running from anywhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from siteassess import auth, crawler, engagement, jsrecon, orchestrator, recon, report, seo  # noqa: E402
from siteassess.client import Client  # noqa: E402


def get_credentials(use_env: bool) -> tuple[str, str]:
    """Obtain credentials WITHOUT persisting them. Returns (user, password)."""
    if use_env:
        user = os.environ.get("ASSESS_USER")
        pwd = os.environ.get("ASSESS_PASS")
        if not user or not pwd:
            print("ERROR: --env-creds set but ASSESS_USER / ASSESS_PASS are not both defined.",
                  file=sys.stderr)
            sys.exit(2)
        return user, pwd
    if not sys.stdin or not sys.stdin.isatty():
        print("ERROR: no interactive terminal for the credential prompt.\n"
              "  Run this command directly in your own terminal, or set\n"
              "  ASSESS_USER / ASSESS_PASS and pass --env-creds.", file=sys.stderr)
        sys.exit(2)
    print("\nEnter admin credentials (input is hidden and never written to disk).")
    try:
        user = input("  Username/email: ").strip()
        pwd = getpass.getpass("  Password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted: no credentials entered.", file=sys.stderr)
        sys.exit(2)
    return user, pwd


def build_client(args) -> Client:
    hosts = {urlparse(args.base).hostname}
    for h in (args.allow_host or []):
        hosts.add(h)
    return Client(
        allowed_hosts={h for h in hosts if h},
        rate_limit_s=args.rate,
        timeout=args.timeout,
    )


def ensure_outdir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def cmd_recon(args) -> None:
    client = build_client(args)
    rec = recon.run(client, args.base)
    out = ensure_outdir(args.out)
    with open(os.path.join(out, "recon.json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, default=str)
    print(f"[+] Recon complete. Missing security headers: "
          f"{list(rec['headers']['missing'].keys())}")
    print(f"[+] Saved {os.path.join(out, 'recon.json')}")


def cmd_login_check(args) -> None:
    """Detect the login form WITHOUT submitting credentials (pre-flight)."""
    client = build_client(args)
    page = client.get(args.login)
    form = auth.find_login_form(page.text, page.url)
    print(f"[*] GET {args.login} -> {page.status_code} ({page.url})")
    if not form:
        print("[-] No login form (password field) detected on this page.")
        return
    print("[+] Login form detected:")
    print(f"    action      : {form.action}")
    print(f"    method      : {form.method}")
    print(f"    user field  : {form.user_field}")
    print(f"    pass field  : {form.pass_field}")
    print(f"    hidden flds : {list(form.hidden.keys()) or 'none (no CSRF token seen)'}")


def cmd_seo(args) -> None:
    """Standalone anonymous SEO / crawlability pass."""
    client = build_client(args)
    out = ensure_outdir(args.out)
    print(f"[*] SEO pass on {args.base} (max {args.max_pages} pages, anonymous)")
    result = seo.run(client, args.base, max_pages=args.max_pages)
    with open(os.path.join(out, "seo.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    md = "\n".join([f"# SEO Report — {urlparse(args.base).hostname}", ""]
                   + report._seo_section(result))
    path = os.path.join(out, "seo_report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"    analyzed {result['summary']['pages_analyzed']} pages")
    print(f"[+] SEO report written to {path}")


def cmd_js(args) -> None:
    """Client-side bundle recon for SPA / Next.js / React apps."""
    client = build_client(args)
    out = ensure_outdir(args.out)
    pages = [args.base] + (args.page or [])
    print(f"[*] JS bundle recon on {len(pages)} page(s)")
    result = jsrecon.run(client, pages, max_scripts=args.max_scripts)
    with open(os.path.join(out, "js.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"    frameworks : {result['frameworks']}")
    print(f"    providers  : {list(result['providers'].keys())}")
    print(f"    scripts    : {len(result['scripts'])}, api paths: {len(result['api_paths'])}, "
          f"routes: {len(result['routes'])}, secret-like: {len(result['secrets'])}, "
          f"source maps: {len(result['source_maps'])}")
    print(f"[+] Saved {os.path.join(out, 'js.json')}")


def cmd_probe(args) -> None:
    """Anonymous GET probe of specific endpoints (status, CORS, JSON shape only)."""
    client = build_client(args)
    out = ensure_outdir(args.out)
    result = recon.probe_endpoints(client, args.base, args.path)
    with open(os.path.join(out, "probe.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    for r in result:
        if "error" in r:
            print(f"    {r['path']:<40} ERROR {r['error']}")
            continue
        cors = " CORS-REFLECTS" if r["cors_reflects_origin"] else (f" ACAO={r['acao']}" if r["acao"] else "")
        loc = f" -> {r['location']}" if r["location"] else ""
        print(f"    {r['path']:<40} {r['status']} {r['content_type'][:30]:<30} {r['length']:>7}B{cors}{loc}")
    print(f"[+] Saved {os.path.join(out, 'probe.json')}")


def _verdict(path: str, anon: dict, authed: dict) -> str:
    a, b = anon.get("status"), authed.get("status")
    if path.startswith("/api/"):
        if a == 200:
            return "EXPOSED to anonymous"
        if a in (401, 403) and b == 200:
            return "gated (good)"
        if a in (401, 403) and b in (401, 403):
            return "denied even when authed (role-restricted?)"
        if a and a >= 500 and b == 200:
            return "anon 5xx but works authed (inconsistent gating)"
        return f"anon {a} / authed {b}"
    if a == 200 and b == 200:
        return "rendered to anonymous (no server-side gate)"
    if a in (301, 302, 303, 307, 308, 401, 403):
        return "gated (good)"
    return f"anon {a} / authed {b}"


def cmd_authcheck(args) -> None:
    """Anonymous vs authenticated diff over the same paths (access-control check)."""
    out = ensure_outdir(args.out)

    print(f"[*] Anonymous pass over {len(args.path)} path(s)")
    anon = {r["path"]: r for r in recon.probe_endpoints(build_client(args), args.base,
                                                        args.path, test_origin=None)}

    auth_client = build_client(args)
    user, pwd = get_credentials(args.env_creds)
    try:
        login_result = auth.login(auth_client, args.login, user, pwd, mode=args.auth_mode,
                                  user_field=args.user_field, callback_url=args.callback_url)
    finally:
        del user, pwd
    ok = login_result.get("authenticated_likely")
    print(f"[*] login mode={login_result.get('mode')} -> {'AUTHENTICATED' if ok else 'NOT authenticated'}")
    if login_result.get("session_user"):
        print(f"    session identity (redacted): {login_result['session_user']}")
    with open(os.path.join(out, "login.json"), "w", encoding="utf-8") as f:
        json.dump(login_result, f, indent=2, default=str)
    if not ok:
        code = login_result.get("auth_error")
        hint = {
            "CredentialsSignin": "credentials rejected (flow OK) — check email/password or --user-field",
            "MissingCSRF": "CSRF handshake failed — flow problem, not your password",
            "Configuration": "server-side Auth.js configuration error",
        }.get(code, "check credentials or --user-field")
        print(f"[-] Login not confirmed (auth_error={code}): {hint}. Skipping authed pass.")
        return

    print(f"[*] Authenticated pass over {len(args.path)} path(s)")
    authed = {r["path"]: r for r in recon.probe_endpoints(auth_client, args.base,
                                                          args.path, test_origin=None)}

    rows = []
    for path in args.path:
        a, b = anon.get(path, {}), authed.get(path, {})
        rows.append({
            "path": path,
            "anon_status": a.get("status"), "anon_length": a.get("length"),
            "auth_status": b.get("status"), "auth_length": b.get("length"),
            "anon_json_shape": a.get("json_shape"), "auth_json_shape": b.get("json_shape"),
            "verdict": _verdict(path, a, b),
        })
        print(f"    {path:<32} anon {str(a.get('status')):>4} {str(a.get('length')):>7}B | "
              f"auth {str(b.get('status')):>4} {str(b.get('length')):>7}B  -> {rows[-1]['verdict']}")

    with open(os.path.join(out, "authcheck.json"), "w", encoding="utf-8") as f:
        json.dump({"login": login_result, "results": rows}, f, indent=2, default=str)
    print(f"[+] Saved {os.path.join(out, 'authcheck.json')}")


def _tool_override(args, name: str) -> bool | None:
    if getattr(args, f"with_{name}", False):
        return True
    if getattr(args, f"without_{name}", False):
        return False
    return None


def cmd_scan(args) -> None:
    """Orchestrated platform scan (native + Docker scanners + optional browser)."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = ensure_outdir(args.out or os.path.join("runs", ts))

    if args.profile == "full" and args.authorized:
        if sys.stdin and sys.stdin.isatty():
            print("** Intrusive profile `full` may run ZAP active scan and Nmap. **")
            confirm = input("Type YES to proceed: ").strip()
            if confirm != "YES":
                print("Aborted.")
                sys.exit(2)
        else:
            print("ERROR: `full` + --authorized requires interactive YES confirmation.", file=sys.stderr)
            sys.exit(2)

    eng = engagement.build_engagement(
        name=args.name or urlparse(args.base).hostname,
        target=args.base,
        profile=args.profile,
        authorized=args.authorized,
        allow_hosts=args.allow_host,
        path_prefix=args.path_prefix,
        with_zap=_tool_override(args, "zap"),
        with_nmap=_tool_override(args, "nmap"),
        with_testssl=_tool_override(args, "testssl"),
        with_browser=_tool_override(args, "browser"),
        authorization_note=args.authorization if args.authorized else "unauthorized-passive-only",
        environment=args.environment,
        rate=args.rate,
        timeout=args.timeout,
    )

    credentials = None
    user = pwd = None
    if args.login:
        user, pwd = get_credentials(args.env_creds)
        credentials = (user, pwd)

    print(f"[*] Platform scan profile={eng.profile} -> {out}")
    try:
        bundle = orchestrator.run_scan(
            eng,
            Path(out),
            login_url=args.login,
            credentials=credentials,
            auth_mode=args.auth_mode,
            user_field=args.user_field,
            callback_url=args.callback_url,
            crawl_starts=args.start,
            max_pages=args.max_pages,
            seo_max_pages=args.seo_max_pages,
        )
    finally:
        if user is not None:
            del user
        if pwd is not None:
            del pwd
        credentials = None

    md = report.build_platform_report(bundle, out_dir=out)
    report_path = os.path.join(out, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md)
    n = len(bundle.get("findings", []))
    print(f"[+] Merged {n} findings -> {report_path}")
    print(f"[+] Artifacts in {out}")


def cmd_full(args) -> None:
    client = build_client(args)
    out = ensure_outdir(args.out)

    print(f"[*] Stage A/B — passive recon on {args.base}")
    rec = recon.run(client, args.base)

    # SEO runs before login: search engines only ever see the anonymous site.
    seo_result = None
    if not args.no_seo:
        print(f"[*] SEO — anonymous crawlability pass (max {args.seo_max_pages} pages)")
        seo_result = seo.run(client, args.base, max_pages=args.seo_max_pages)
        print(f"    analyzed {seo_result['summary']['pages_analyzed']} pages")

    login_result = None
    if args.login:
        print(f"[*] Stage C — authenticated login at {args.login}")
        user, pwd = get_credentials(args.env_creds)
        try:
            login_result = auth.login(client, args.login, user, pwd, mode=args.auth_mode,
                                      user_field=args.user_field, callback_url=args.callback_url)
        finally:
            # Drop plaintext secrets from memory as soon as possible.
            del user, pwd
        status = "likely authenticated" if login_result.get("authenticated_likely") else "NOT confirmed"
        print(f"    login: mode={login_result.get('mode')} -> {status}")

    print(f"[*] Stage D/E/F — authenticated crawl (max {args.max_pages} pages)")
    starts = [args.base]
    if args.login:
        starts.append(login_result.get("final_url", args.login) if login_result else args.login)
    for s in (args.start or []):
        starts.append(urljoin(args.base, s))
    crawl = crawler.crawl(client, starts, max_pages=args.max_pages,
                          same_path_prefix=args.path_prefix)
    print(f"    crawled {crawl['pages_crawled']} pages, {len(crawl['findings'])} raw findings")

    engagement = {
        "name": args.name or urlparse(args.base).hostname,
        "target": args.base,
        "authorization": args.authorization,
        "environment": args.environment,
        "depth": "passive recon + authenticated review + safe active checks",
        "timestamp": datetime.now().astimezone().isoformat(),
    }

    # Persist raw artifacts (credentials never appear here; the client redacts sent data).
    with open(os.path.join(out, "recon.json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, default=str)
    with open(os.path.join(out, "crawl.json"), "w", encoding="utf-8") as f:
        json.dump(crawl, f, indent=2, default=str)
    if login_result is not None:
        with open(os.path.join(out, "login.json"), "w", encoding="utf-8") as f:
            json.dump(login_result, f, indent=2, default=str)
    if seo_result is not None:
        with open(os.path.join(out, "seo.json"), "w", encoding="utf-8") as f:
            json.dump(seo_result, f, indent=2, default=str)
    with open(os.path.join(out, "request_log.json"), "w", encoding="utf-8") as f:
        json.dump(client.log, f, indent=2, default=str)

    md = report.build(engagement, rec, login_result, crawl, seo_result)
    report_path = os.path.join(out, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[+] Report written to {report_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="Non-destructive web app assessment toolkit.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--base", required=True, help="Base in-scope URL.")
        sp.add_argument("--allow-host", action="append", help="Extra in-scope host (repeatable).")
        sp.add_argument("--rate", type=float, default=1.0, help="Min seconds between requests.")
        sp.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout seconds.")
        sp.add_argument("--out", default="assessment_output", help="Output directory.")

    sp_recon = sub.add_parser("recon", help="Passive recon only.")
    common(sp_recon)
    sp_recon.set_defaults(func=cmd_recon)

    sp_lc = sub.add_parser("login-check", help="Detect login form without submitting.")
    common(sp_lc)
    sp_lc.add_argument("--login", required=True, help="Login/admin URL.")
    sp_lc.set_defaults(func=cmd_login_check)

    sp_seo = sub.add_parser("seo", help="Anonymous SEO / crawlability checks only.")
    common(sp_seo)
    sp_seo.add_argument("--max-pages", type=int, default=40, help="Crawl page cap.")
    sp_seo.set_defaults(func=cmd_seo)

    sp_js = sub.add_parser("js", help="Client-side JS bundle recon (SPA / Next.js).")
    common(sp_js)
    sp_js.add_argument("--page", action="append", help="Extra in-scope page to analyze (repeatable).")
    sp_js.add_argument("--max-scripts", type=int, default=60, help="Cap on bundles downloaded.")
    sp_js.set_defaults(func=cmd_js)

    sp_probe = sub.add_parser("probe", help="Anonymous GET probe of given endpoints.")
    common(sp_probe)
    sp_probe.add_argument("--path", action="append", required=True, help="Path to probe (repeatable).")
    sp_probe.set_defaults(func=cmd_probe)

    def auth_opts(sp):
        sp.add_argument("--auth-mode", choices=["auto", "form", "authjs"], default="auto",
                        help="Login style; auto-detects HTML form vs Auth.js/NextAuth.")
        sp.add_argument("--user-field", help="Credential field name for the username "
                        "(Auth.js default: email).")
        sp.add_argument("--callback-url", help="Post-login callback URL (Auth.js).")
        sp.add_argument("--env-creds", action="store_true",
                        help="Read ASSESS_USER/ASSESS_PASS from env instead of prompting.")

    sp_ac = sub.add_parser("authcheck", help="Anonymous vs authenticated access-control diff.")
    common(sp_ac)
    auth_opts(sp_ac)
    sp_ac.add_argument("--login", required=True, help="Login URL (form page or Auth.js app).")
    sp_ac.add_argument("--path", action="append", required=True, help="Path to compare (repeatable).")
    sp_ac.set_defaults(func=cmd_authcheck)

    sp_scan = sub.add_parser(
        "scan",
        help="Orchestrated scan: native + ZAP/Nmap/testssl (Docker) + Playwright.",
    )
    common(sp_scan)
    auth_opts(sp_scan)
    sp_scan.add_argument(
        "--profile",
        choices=engagement.PROFILES,
        default="passive",
        help="Scan intensity (default: passive).",
    )
    sp_scan.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm written authorization for intrusive stages (Nmap, ZAP full).",
    )
    sp_scan.add_argument("--with-zap", action="store_true", help="Force-enable OWASP ZAP.")
    sp_scan.add_argument("--without-zap", action="store_true", help="Disable ZAP.")
    sp_scan.add_argument("--with-nmap", action="store_true", help="Force-enable Nmap.")
    sp_scan.add_argument("--without-nmap", action="store_true", help="Disable Nmap.")
    sp_scan.add_argument("--with-testssl", action="store_true", help="Force-enable testssl.sh.")
    sp_scan.add_argument("--without-testssl", action="store_true", help="Disable testssl.sh.")
    sp_scan.add_argument("--with-browser", action="store_true", help="Force-enable Playwright.")
    sp_scan.add_argument("--without-browser", action="store_true", help="Disable Playwright.")
    sp_scan.add_argument("--login", help="Login URL for authenticated crawl/browser.")
    sp_scan.add_argument("--start", action="append", help="Extra crawl seed paths.")
    sp_scan.add_argument("--path-prefix", help="Crawl only URLs under this path prefix.")
    sp_scan.add_argument("--max-pages", type=int, default=60)
    sp_scan.add_argument("--seo-max-pages", type=int, default=40)
    sp_scan.add_argument("--name", help="Engagement name for the report.")
    sp_scan.add_argument("--authorization", default="client-authorized")
    sp_scan.add_argument("--environment", default="production")
    sp_scan.set_defaults(func=cmd_scan, out=None)

    sp_full = sub.add_parser("full", help="Recon + SEO + login + authenticated crawl + report.")
    common(sp_full)
    sp_full.add_argument("--auth-mode", choices=["auto", "form", "authjs"], default="auto",
                         help="Login style; auto-detects HTML form vs Auth.js/NextAuth.")
    sp_full.add_argument("--user-field", help="Credential field name for the username.")
    sp_full.add_argument("--callback-url", help="Post-login callback URL (Auth.js).")
    sp_full.add_argument("--no-seo", action="store_true", help="Skip the SEO pass.")
    sp_full.add_argument("--seo-max-pages", type=int, default=40, help="SEO crawl page cap.")
    sp_full.add_argument("--login", help="Login/admin URL to authenticate against.")
    sp_full.add_argument("--path-prefix", help="Only crawl URLs whose path starts with this.")
    sp_full.add_argument("--start", action="append",
                         help="Extra crawl seed URL or path, e.g. /admin/dashboard (repeatable).")
    sp_full.add_argument("--max-pages", type=int, default=60, help="Crawl page cap.")
    sp_full.add_argument("--env-creds", action="store_true",
                         help="Read ASSESS_USER/ASSESS_PASS from env instead of prompting.")
    sp_full.add_argument("--name", help="Engagement name for the report.")
    sp_full.add_argument("--authorization", default="client-authorized",
                         help="Authorization note for the report.")
    sp_full.add_argument("--environment", default="production")
    sp_full.set_defaults(func=cmd_full)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

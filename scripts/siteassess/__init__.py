"""
siteassess - a general-purpose, non-destructive web application assessment toolkit.

Modules:
    client   - scope-aware HTTP session with rate limiting and secret redaction
    recon    - passive recon: security headers, TLS, cookies, tech fingerprint, robots/sitemap
    auth     - generic HTML form login (auto-detects the login form)
    crawler  - authenticated, in-scope BFS crawl collecting links, forms and heuristic findings
    report        - renders a Markdown report from collected results
    findings      - unified finding schema + merge across scanners
    orchestrator  - `scan` pipeline (native + Docker tools + Playwright)
    engagement    - scope, profiles, authorization gates

Design goals:
    * Reusable against any authorized target (nothing target-specific is hardcoded).
    * Safe by default: GET/HEAD, conservative rate limit, stays in scope, no exploitation.
    * Credentials are never written to disk; they come from a prompt or environment.
"""

__version__ = "1.0.0"

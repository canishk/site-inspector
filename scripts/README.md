# siteassess — reusable web app assessment toolkit

**Utilization guide (setup, workflows, examples, troubleshooting):** see the project [README.md](../README.md).

A small, **non-destructive**, general-purpose toolkit for authorized web application
security assessments. Nothing is hardcoded to a specific site — point it at any target
you are authorized to test.

## What it does

| Stage | Module | Checks |
|---|---|---|
| Passive recon | `siteassess/recon.py` | security headers, TLS cert/protocol, cookie flags, tech fingerprint, HTTP→HTTPS, common sensitive paths, endpoint probe |
| JS recon | `siteassess/jsrecon.py` | SPA/Next.js bundles: frameworks, routes, API paths, secret scan, source maps |
| Auth | `siteassess/auth.py` | auto-detects **HTML form** vs **Auth.js/NextAuth** and signs in; reports success/failure + error code |
| Crawl | `siteassess/crawler.py` | in-scope BFS crawl, link + form inventory, passive finding heuristics |
| SEO | `siteassess/seo.py` | titles, descriptions, canonicals, H1, structured data, robots/sitemap |
| Report | `siteassess/report.py` | Markdown report with scorecard + findings register |

## Install

```powershell
pip install -r requirements.txt
playwright install chromium
```

**Platform scan (ZAP / Nmap / testssl.sh)** requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) on Windows. Images are pulled on first use:

- `ghcr.io/zaproxy/zaproxy:stable`
- `drwetter/testssl.sh`
- `instrumentisto/nmap`

If Docker or Playwright is missing, those stages are recorded as **skipped** in `coverage.json`; native recon/crawl still run.

## Usage

### Orchestrated platform scan (recommended)

One command runs native checks plus optional Docker scanners and Playwright. Output defaults to `runs/<timestamp>/`.

```powershell
# Passive: native recon, crawl, SEO, testssl only (no port scan / ZAP active)
python assess.py scan --base https://example.com/ --profile passive

# Safe-active: + ZAP baseline, Nmap, Playwright (requires --authorized)
python assess.py scan --base https://example.com/ --profile safe-active --authorized

# Full: may run ZAP *active* scan (interactive YES required)
python assess.py scan --base https://example.com/ --profile full --authorized

# With admin login (credentials prompted or ASSESS_USER/ASSESS_PASS + --env-creds)
python assess.py scan --base https://example.com/ `
  --profile safe-active --authorized `
  --login https://example.com/admin/login --auth-mode auto
```

Override tools: `--with-zap` / `--without-zap`, `--with-nmap`, `--with-testssl`, `--with-browser`.

Artifacts: `report.md`, `findings.json`, `coverage.json`, `raw/*`, plus `recon.json`, `crawl.json`, etc.

Profiles are documented in [config/profiles.yaml](config/profiles.yaml).

---

Passive recon only (no credentials):

```powershell
python assess.py recon --base https://example.com/app/ --out ..\assessment_output
```

Full authenticated assessment:

```powershell
python assess.py full `
  --base https://example.com/app/ `
  --login https://example.com/app/admin `
  --path-prefix /app/ `
  --max-pages 80 `
  --out ..\assessment_output
```

Single-page apps (Next.js/React) — inspect client bundles and probe endpoints:

```powershell
python assess.py js    --base https://example.com/ --page https://example.com/admin/login
python assess.py probe --base https://example.com/ --path /api/users --path /admin/dashboard
```

Access-control diff — anonymous vs authenticated over the same paths:

```powershell
python assess.py authcheck `
  --base https://example.com/ `
  --login https://example.com/admin/login `
  --path /admin/dashboard --path /api/users `
  --out ..\assessment_output
```

Each path gets a verdict such as `rendered to anonymous (no server-side gate)`,
`EXPOSED to anonymous`, or `gated (good)`. Login style is auto-detected; force it
with `--auth-mode form|authjs`, and set `--user-field` if the username field is not
`email`. On an Auth.js failure the error code is reported:
`CredentialsSignin` (password rejected, flow OK), `MissingCSRF` (flow problem), or
`Configuration` (server-side `authorize` threw — often a backend/database fault).

`tools/page_summary.py URL ...` summarizes what an anonymous visitor receives from a
page, to tell a real access-control failure apart from an empty client shell.

## Credentials — never stored

- **Default:** you are prompted at runtime; the password is read with `getpass`
  (hidden) and only held in memory for the single login request.
- **Alternative:** set `ASSESS_USER` / `ASSESS_PASS` env vars and pass `--env-creds`.
- Credentials are **never** written to any output file. The request log redacts all
  sensitive headers and form fields.

Run the `full` command yourself in an interactive terminal so the credential prompt
works and the secret never leaves your machine.

## Safety model

- Requests are confined to the host of `--base` (plus any `--allow-host`).
- Conservative rate limit (`--rate`, default 1 req/s).
- GET/HEAD only, except the single authenticated login POST.
- Links matching `logout|delete|reset|...` are inventoried but **not followed**.
- No exploitation, fuzzing, brute force, or destructive actions.

## Output

Written to `--out` (default `assessment_output/`):

- `report.md` — the human-readable report
- `recon.json`, `crawl.json`, `login.json` — raw structured results
- `request_log.json` — redacted log of every request made

## Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

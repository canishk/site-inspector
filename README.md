# Site Inspector — Web Application Security Assessment

General-purpose, **authorized-only** toolkit for assessing web applications. It combines built-in passive checks with optional **OWASP ZAP**, **Nmap**, **testssl.sh** (via Docker), and **Playwright** browser automation. Nothing is tied to a specific site—point it at any target you own or are permitted to test.

All work happens under [`scripts/`](scripts/). Run commands from that directory unless noted otherwise.

---

## Before you start

1. **Authorization** — You must own the target or have written permission. Intrusive stages require `--authorized` (and `full` profile requires typing `YES`).
2. **Python 3.10+** on your machine.
3. **Optional but recommended**
   - [Docker Desktop](https://www.docker.com/products/docker-desktop/) — for ZAP, Nmap, testssl.sh
   - Playwright Chromium — for browser automation (`playwright install chromium`)

---

## Quick setup (Windows)

```powershell
cd C:\Users\canis\Projects\site-inspector\scripts
pip install -r requirements.txt
playwright install chromium
```

Verify the CLI:

```powershell
python assess.py --help
python assess.py scan --help
```

Run unit tests (no network):

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

---

## Which command should I use?

| Goal | Command |
|------|---------|
| **One-shot assessment (recommended)** | `assess.py scan` |
| Headers, TLS, cookies only | `assess.py recon` |
| Legacy full pipeline (recon + SEO + crawl + report) | `assess.py full` |
| SPA / Next.js bundle analysis | `assess.py js` |
| Hit specific URLs/APIs anonymously | `assess.py probe` |
| SEO / crawlability only | `assess.py seo` |
| Anonymous vs logged-in access diff | `assess.py authcheck` |
| Pre-flight: detect login form fields | `assess.py login-check` |
| Human-readable page summary (debug) | `python tools\page_summary.py <URL>` |

---

## Orchestrated scan (`scan`) — main workflow

`scan` runs native checks, merges findings from all sources, and writes a single `report.md`.

### Profiles

| Profile | What runs by default |
|---------|----------------------|
| `passive` | Native recon, JS recon, SEO, crawl, **testssl** (no ZAP/Nmap/browser) |
| `safe-active` | Above + **ZAP baseline**, **Nmap**, **Playwright** (needs `--authorized`) |
| `full` | Above + **ZAP active** scan (needs `--authorized` + interactive `YES`) |

Defaults are defined in [`scripts/config/profiles.yaml`](scripts/config/profiles.yaml). Override per tool:

`--with-zap` / `--without-zap`, `--with-nmap` / `--without-nmap`, `--with-testssl` / `--without-testssl`, `--with-browser` / `--without-browser`

### Example 1 — Passive only (no credentials)

```powershell
python assess.py scan `
  --base https://example.com/ `
  --profile passive `
  --out ..\my_run_passive
```

### Example 2 — Safe-active with Docker scanners

```powershell
python assess.py scan `
  --base https://example.com/ `
  --profile safe-active `
  --authorized `
  --out ..\my_run_safe
```

### Example 3 — Authenticated admin (PHP-style HTML login)

Run in your **own terminal** so the password prompt works (hidden input, never saved to disk).

```powershell
python assess.py scan `
  --base https://example.com/job-portal/ `
  --profile safe-active `
  --authorized `
  --login https://example.com/job-portal/admin `
  --auth-mode form `
  --path-prefix /job-portal/ `
  --start /job-portal/admin/dashboard `
  --max-pages 80 `
  --out ..\assessment_client
```

### Example 4 — Auth.js / Next.js (e.g. Vercel app)

Login is client-rendered; use `authjs` or `auto`.

```powershell
# Option A: prompt for credentials
python assess.py scan `
  --base https://your-app.vercel.app/ `
  --profile safe-active `
  --authorized `
  --login https://your-app.vercel.app/admin/login `
  --auth-mode authjs `
  --start /admin/dashboard `
  --out ..\assessment_spa

# Option B: env vars (still not written to disk)
$env:ASSESS_USER = "admin@example.com"
$env:ASSESS_PASS = "your-password"
python assess.py scan --base https://your-app.vercel.app/ --login https://your-app.vercel.app/admin/login --auth-mode authjs --env-creds --authorized --profile safe-active
Remove-Item Env:ASSESS_USER, Env:ASSESS_PASS
```

### Example 5 — Full intrusive ZAP

Requires interactive confirmation:

```powershell
python assess.py scan `
  --base https://example.com/ `
  --profile full `
  --authorized
# Type YES when prompted
```

### Useful flags

| Flag | Purpose |
|------|---------|
| `--base` | Target URL (required) |
| `--allow-host` | Extra in-scope hostnames (repeatable) |
| `--rate` | Minimum seconds between HTTP requests (default `1.0`) |
| `--timeout` | Per-request timeout seconds |
| `--out` | Output folder (`scan` defaults to `runs/<timestamp>` if omitted) |
| `--name` | Engagement name in the report |
| `--authorization` | Text for the report (e.g. `client-authorized`) |
| `--environment` | `production` / `staging` |

---

## Standalone commands (granular control)

All commands accept `--base`, `--out`, `--rate`, `--timeout`, `--allow-host`.

### Recon

```powershell
python assess.py recon --base https://example.com/ --out ..\assessment_output
```

Produces `recon.json` (headers, TLS, cookies, probed paths).

### JavaScript / SPA recon

```powershell
python assess.py js --base https://example.com/ `
  --page https://example.com/admin/login `
  --out ..\assessment_output
```

Produces `js.json` (frameworks, API paths, routes, secret heuristics).

### Endpoint probe

```powershell
python assess.py probe --base https://example.com/ `
  --path /api/users --path /admin/dashboard --path /api/auth/session `
  --out ..\assessment_output
```

Produces `probe.json` (status, CORS, JSON shape).

### Access-control check (anonymous vs authenticated)

```powershell
python assess.py authcheck `
  --base https://example.com/ `
  --login https://example.com/admin/login `
  --auth-mode auto `
  --path /admin/dashboard --path /api/applications `
  --out ..\assessment_output
```

Produces `authcheck.json` with per-path **verdicts**.

### SEO pass

```powershell
python assess.py seo --base https://example.com/ --max-pages 40 --out ..\assessment_output
```

Produces `seo_report.md` and `seo.json`.

### Classic `full` (without Docker scanners)

```powershell
python assess.py full `
  --base https://example.com/ `
  --login https://example.com/admin `
  --path-prefix /app/ `
  --max-pages 80 `
  --out ..\assessment_output
```

Same family as before `scan` existed: recon, SEO, login, crawl, legacy `report.md`.

---

## Credentials

| Method | When to use |
|--------|-------------|
| **Interactive prompt** | Default; run in a real terminal |
| **`--env-creds`** | CI or scripted runs; set `ASSESS_USER` and `ASSESS_PASS` in the shell session only |

Passwords are **never** written to `report.md`, JSON artifacts, or git. Request logs redact sensitive form fields and headers.

**Auth modes**

- `auto` — HTML form if present, else Auth.js (`/api/auth/providers`)
- `form` — classic `<form>` + password field
- `authjs` — NextAuth / Auth.js credentials flow

If Auth.js login fails, check `login.json` for `auth_error`: `CredentialsSignin`, `MissingCSRF`, or `Configuration`.

---

## Understanding output

### After `scan`

| File | Contents |
|------|----------|
| `report.md` | Executive summary, tool coverage, merged findings |
| `findings.json` | Normalized findings from all sources |
| `coverage.json` | Each stage: `ran` / `skipped` / `failed` + reason |
| `recon.json` | Headers, TLS, paths |
| `crawl.json` | Pages visited, heuristic findings |
| `seo.json` | SEO issues |
| `js.json` | Bundle recon |
| `login.json` | Login attempt result (no secrets) |
| `request_log.json` | Redacted HTTP log |
| `raw/` | ZAP, Nmap, testssl, browser outputs when Docker/tools succeed |

### Severity (security)

`Critical` → `High` → `Medium` → `Low` → `Informational`. Scanners and heuristics are **leads**—confirm in code or config before treating as production defects.

### When tools are skipped

Common reasons in `coverage.json`:

- `docker not found on PATH` — install Docker Desktop
- `playwright not installed` — `pip install playwright` + `playwright install chromium`
- `requires --authorized` — add `--authorized` for Nmap / ZAP full
- `full scan requires --authorized` — same for active ZAP

Native recon and crawl still run when Docker is absent.

---

## Docker images (first run pulls)

| Tool | Image |
|------|--------|
| OWASP ZAP | `ghcr.io/zaproxy/zaproxy:stable` |
| testssl.sh | `drwetter/testssl.sh` |
| Nmap | `instrumentisto/nmap` |

---

## Safety rules (built in)

- Requests stay on `--base` host (+ `--allow-host` only).
- No brute force, fuzzing, or exploitation.
- Dangerous links (`logout`, `delete`, …) are not followed during crawl.
- Nmap and ZAP active scans need `--authorized`; `full` needs typed `YES`.
- Scope URLs only are passed into containers (no credentials in Docker argv).

---

## Troubleshooting

| Symptom | What to do |
|---------|------------|
| `EOFError` on login | Run in interactive terminal, or use `--env-creds` |
| Auth.js `Configuration` | Often server/DB misconfig; fix app before relying on authed tests |
| `form_detected: false` on SPA | Use `--auth-mode authjs` |
| Empty ZAP findings | Check `raw/` and Docker logs; ensure target is reachable from container |
| Slow scan | Lower `--max-pages`, raise `--rate`, or use `--profile passive` |
| Admin pages not crawled | Add `--start /admin/dashboard` (and other seeds) |

---

## Project layout

```
site-inspector/
  README.md                 ← this guide
  scripts/
    assess.py               ← CLI entrypoint
    requirements.txt
    config/profiles.yaml    ← scan profile reference
    siteassess/             ← core library
      orchestrator.py       ← scan pipeline
      findings.py           ← unified findings
      tools/                ← ZAP, Nmap, testssl, browser adapters
    tests/                  ← normalizer unit tests
    tools/page_summary.py   ← debug helper
```

For module-level detail, see [`scripts/README.md`](scripts/README.md).

---

## Legal

Use only against systems you are **authorized** to test. You are responsible for complying with applicable laws and contracts.

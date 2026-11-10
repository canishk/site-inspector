"""Generic authentication.

Supports two login styles and auto-detects which one a target uses:

  * "form"   - a classic server-rendered HTML <form> with a password field.
  * "authjs" - Auth.js / NextAuth credentials flow (SPA apps with /api/auth/*):
               GET /api/auth/csrf -> POST /api/auth/callback/credentials ->
               verify via GET /api/auth/session.

No credentials are logged or stored; results are redacted.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup

from .client import Client

# Field-name heuristics (lowercased substring match).
USER_FIELD_HINTS = ["user", "email", "login", "name", "account", "uname", "uid"]
PASS_FIELD_HINTS = ["pass", "pwd", "pw"]


@dataclass
class LoginForm:
    action: str
    method: str
    user_field: str | None
    pass_field: str | None
    hidden: dict           # extra fields to carry (csrf tokens, etc.)


def find_login_form(html: str, page_url: str) -> LoginForm | None:
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        inputs = form.find_all(["input", "button"])
        pass_field = None
        user_field = None
        hidden = {}
        for el in inputs:
            itype = (el.get("type") or ("submit" if el.name == "button" else "text")).lower()
            name = el.get("name")
            if not name:
                continue
            if itype == "submit":
                # Many PHP handlers gate on isset($_POST['<submit name>']).
                hidden.setdefault(name, el.get("value", ""))
            elif itype == "password" and pass_field is None:
                pass_field = name
            elif itype == "hidden":
                hidden[name] = el.get("value", "")
            elif itype in ("text", "email", "tel") and user_field is None:
                if any(h in name.lower() for h in USER_FIELD_HINTS) or user_field is None:
                    user_field = name
        if pass_field:
            # Guess the user field if none matched the hints yet.
            if user_field is None:
                for el in inputs:
                    name = el.get("name")
                    itype = (el.get("type") or "text").lower()
                    if name and itype in ("text", "email"):
                        user_field = name
                        break
            action = urljoin(page_url, form.get("action") or page_url)
            method = (form.get("method") or "post").lower()
            return LoginForm(action, method, user_field, pass_field, hidden)
    return None


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def detect_mode(client: Client, login_url: str) -> str:
    """Decide whether to use the HTML-form or Auth.js flow for this target."""
    page = client.get(login_url)
    if find_login_form(page.text, page.url):
        return "form"
    # Auth.js exposes a providers endpoint at the site origin.
    try:
        r = client.get(urljoin(_origin(page.url), "/api/auth/providers"))
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            return "authjs"
    except Exception:
        pass
    return "unknown"


def _summarize_session_user(data) -> dict:
    """Extract non-sensitive identity signals from an Auth.js session object."""
    if not isinstance(data, dict):
        return {}
    user = data.get("user", data)
    out = {}
    for key in ("role", "type", "userType", "isAdmin", "status"):
        if isinstance(user, dict) and key in user:
            out[key] = user[key]
    if isinstance(user, dict):
        email = user.get("email")
        if email and "@" in email:
            out["email_domain"] = email.split("@", 1)[1]
        out["has_name"] = bool(user.get("name"))
        out["fields_present"] = sorted(user.keys())
    return out


def authjs_login(
    client: Client,
    base_url: str,
    username: str,
    password: str,
    *,
    user_field: str = "email",
    pass_field: str = "password",
    callback_url: str | None = None,
    extra: dict | None = None,
) -> dict:
    """Perform an Auth.js (NextAuth) credentials sign-in. Returns a redacted result."""
    origin = _origin(base_url)
    result: dict = {"login_url": base_url, "mode": "authjs",
                    "user_field": user_field, "pass_field": pass_field}

    csrf_resp = client.get(urljoin(origin, "/api/auth/csrf"))
    try:
        csrf_token = csrf_resp.json().get("csrfToken")
    except ValueError:
        csrf_token = None
    result["csrf_obtained"] = bool(csrf_token)
    if not csrf_token:
        result["authenticated_likely"] = False
        result["error"] = "no csrfToken from /api/auth/csrf"
        return result

    data = {
        "csrfToken": csrf_token,
        "callbackUrl": callback_url or base_url,
        "json": "true",
        user_field: username,
        pass_field: password,
    }
    if extra:
        data.update(extra)

    post = client.post(
        urljoin(origin, "/api/auth/callback/credentials"),
        data=data,
        allow_redirects=False,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    result["callback_status"] = post.status_code
    # Auth.js signals failure by redirecting/returning a URL containing ?error=<Code>.
    # The code distinguishes a rejected password (CredentialsSignin) from a broken
    # flow (MissingCSRF, Configuration), which matters for diagnosing a failed run.
    loc = post.headers.get("Location", "")
    body_url = ""
    try:
        body_url = post.json().get("url", "")
    except ValueError:
        pass
    err_src = loc if "error=" in loc else body_url
    result["error_in_response"] = "error=" in err_src
    if result["error_in_response"]:
        code = parse_qs(urlparse(err_src).query).get("error", [""])[0]
        result["auth_error"] = code or "unknown"

    # Authoritative check: does the session endpoint now return a user?
    sess = client.get(urljoin(origin, "/api/auth/session"))
    user = None
    try:
        user = sess.json()
    except ValueError:
        pass
    authenticated = bool(user) and not result["error_in_response"]
    result.update(
        {
            "session_status": sess.status_code,
            "session_user": _summarize_session_user(user) if authenticated else {},
            "authenticated_likely": authenticated,
        }
    )
    return result


def login(
    client: Client,
    login_url: str,
    username: str,
    password: str,
    *,
    mode: str = "auto",
    user_field: str | None = None,
    callback_url: str | None = None,
) -> dict:
    """Unified login dispatcher: auto-detects form vs Auth.js unless forced."""
    chosen = mode
    if mode == "auto":
        chosen = detect_mode(client, login_url)
    if chosen == "authjs":
        return authjs_login(
            client, login_url, username, password,
            user_field=user_field or "email", callback_url=callback_url,
        )
    return form_login(client, login_url, username, password)


def form_login(client: Client, login_url: str, username: str, password: str) -> dict:
    """Attempt a single HTML-form login. Returns a redacted result dict."""
    page = client.get(login_url)
    form = find_login_form(page.text, page.url)
    result: dict = {"login_url": login_url, "mode": "form", "form_detected": form is not None}
    if not form:
        return result

    result["action"] = form.action
    result["user_field"] = form.user_field
    result["pass_field"] = form.pass_field
    result["hidden_fields"] = list(form.hidden.keys())

    data = dict(form.hidden)
    if form.user_field:
        data[form.user_field] = username
    data[form.pass_field] = password

    if form.method == "get":
        resp = client.get(form.action, params=data)
    else:
        resp = client.post(form.action, data=data)

    # Heuristic success detection.
    body = resp.text.lower()
    failure_markers = ["invalid", "incorrect", "failed", "try again", "wrong", "denied"]
    logout_markers = ["logout", "log out", "sign out", "dashboard", "welcome"]
    looks_failed = any(m in body for m in failure_markers)
    looks_in = any(m in body for m in logout_markers) and not looks_failed
    got_cookie = bool(resp.cookies) or bool(client.session.cookies)

    result.update(
        {
            "post_status": resp.status_code,
            "final_url": resp.url,
            "redirected": resp.url != form.action,
            "set_cookie": got_cookie,
            "failure_marker_found": looks_failed,
            "authenticated_likely": bool(looks_in or (resp.url != form.action and got_cookie and not looks_failed)),
        }
    )
    return result

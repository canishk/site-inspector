"""Engagement scope, authorization gate, and scan profiles."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


PROFILES = ("passive", "safe-active", "full")

# Default tool toggles per profile (CLI flags can override).
PROFILE_DEFAULTS: dict[str, dict] = {
    "passive": {
        "native": True,
        "zap": False,
        "nmap": False,
        "testssl": True,
        "browser": False,
        "zap_mode": None,
    },
    "safe-active": {
        "native": True,
        "zap": True,
        "nmap": True,
        "testssl": True,
        "browser": True,
        "zap_mode": "baseline",
    },
    "full": {
        "native": True,
        "zap": True,
        "nmap": True,
        "testssl": True,
        "browser": True,
        "zap_mode": "full",
    },
}


@dataclass
class Scope:
    base_url: str
    allowed_hosts: set[str] = field(default_factory=set)
    path_prefix: str | None = None
    rate_limit_s: float = 1.0
    request_timeout: float = 20.0

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            host = urlparse(self.base_url).hostname
            if host:
                self.allowed_hosts = {host.lower()}


@dataclass
class Engagement:
    name: str
    target: str
    authorized: bool
    profile: str
    authorization_note: str = "client-authorized"
    environment: str = "production"
    scope: Scope | None = None
    # Resolved tool flags (after profile + CLI overrides).
    use_native: bool = True
    use_zap: bool = False
    use_nmap: bool = False
    use_testssl: bool = True
    use_browser: bool = False
    zap_mode: str | None = None  # baseline | full


def require_authorization(engagement: Engagement, intrusive: bool) -> None:
    if intrusive and not engagement.authorized:
        raise PermissionError(
            "Intrusive stages (ZAP full scan, aggressive Nmap) require --authorized "
            "and client-written permission to test this target."
        )


def resolve_tools(
    profile: str,
    *,
    with_zap: bool | None = None,
    with_nmap: bool | None = None,
    with_testssl: bool | None = None,
    with_browser: bool | None = None,
) -> dict:
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile {profile!r}; choose from {PROFILES}")
    cfg = dict(PROFILE_DEFAULTS[profile])
    if with_zap is not None:
        cfg["zap"] = with_zap
    if with_nmap is not None:
        cfg["nmap"] = with_nmap
    if with_testssl is not None:
        cfg["testssl"] = with_testssl
    if with_browser is not None:
        cfg["browser"] = with_browser
    return cfg


def build_engagement(
    *,
    name: str,
    target: str,
    profile: str,
    authorized: bool,
    allow_hosts: list[str] | None = None,
    path_prefix: str | None = None,
    with_zap: bool | None = None,
    with_nmap: bool | None = None,
    with_testssl: bool | None = None,
    with_browser: bool | None = None,
    authorization_note: str = "client-authorized",
    environment: str = "production",
    rate: float = 1.0,
    timeout: float = 20.0,
) -> Engagement:
    tools = resolve_tools(
        profile,
        with_zap=with_zap,
        with_nmap=with_nmap,
        with_testssl=with_testssl,
        with_browser=with_browser,
    )
    hosts = {urlparse(target).hostname or ""}
    for h in allow_hosts or []:
        if h:
            hosts.add(h.lower())
    scope = Scope(
        base_url=target,
        allowed_hosts={h for h in hosts if h},
        path_prefix=path_prefix,
        rate_limit_s=rate,
        request_timeout=timeout,
    )
    return Engagement(
        name=name or (urlparse(target).hostname or "target"),
        target=target,
        authorized=authorized,
        profile=profile,
        authorization_note=authorization_note,
        environment=environment,
        scope=scope,
        use_native=tools["native"],
        use_zap=tools["zap"],
        use_nmap=tools["nmap"],
        use_testssl=tools["testssl"],
        use_browser=tools["browser"],
        zap_mode=tools.get("zap_mode"),
    )

"""Unified finding schema and merge/dedupe across scanners."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCE_LEVELS = ("High", "Medium", "Low")

# External tool severity maps
ZAP_RISKCODE = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational", "-1": "Informational"}
TESTSSL_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "OK": "Informational",
    "INFO": "Informational",
    "WARN": "Low",
}


@dataclass
class Finding:
    id: str
    source: str
    severity: str
    confidence: str
    title: str
    owasp_category: str
    url: str
    evidence: str
    remediation: str
    raw_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def make_id(source: str, title: str, url: str) -> str:
        h = hashlib.sha256(f"{source}|{title}|{url}".encode()).hexdigest()[:12]
        return f"{source}-{h}"


@dataclass
class StageCoverage:
    name: str
    status: str  # ran | skipped | failed
    detail: str = ""
    raw_path: str = ""


def normalize_severity(value: str, mapping: dict[str, str] | None = None) -> str:
    if mapping:
        return mapping.get(value.upper(), mapping.get(value, "Informational"))
    if value in SEVERITIES:
        return value
    return "Informational"


def merge(findings: list[Finding]) -> list[Finding]:
    """Dedupe by (source, title, url); keep highest severity on collision."""
    by_key: dict[str, Finding] = {}
    for f in findings:
        key = f"{f.source}|{f.title}|{f.url}"
        cur = by_key.get(key)
        if cur is None:
            by_key[key] = f
            continue
        if SEVERITY_ORDER.get(f.severity, 9) < SEVERITY_ORDER.get(cur.severity, 9):
            by_key[key] = f
    return sorted(by_key.values(), key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.title))


def from_crawl(crawl: dict) -> list[Finding]:
    from .report import FINDING_META  # avoid circular at import time

    out: list[Finding] = []
    for f in crawl.get("findings", []):
        ftype = f.get("type", "unknown")
        sev, cat, fix = FINDING_META.get(ftype, ("Informational", "Other", "Review."))
        url = f.get("url") or ""
        title = ftype.replace("_", " ").title()
        detail = f.get("detail") or ""
        out.append(
            Finding(
                id=Finding.make_id("native-crawl", title, url),
                source="native-crawl",
                severity=sev,
                confidence="Medium",
                title=title,
                owasp_category=cat,
                url=url,
                evidence=detail[:500],
                remediation=fix,
                raw_ref="crawl.json",
            )
        )
    return out


def from_recon_headers(recon: dict) -> list[Finding]:
    missing = recon.get("headers", {}).get("missing", {})
    out: list[Finding] = []
    base = recon.get("base_url", "")
    for hdr, why in missing.items():
        if hdr == "content-security-policy":
            sev = "Medium"
        elif hdr in ("strict-transport-security", "x-frame-options"):
            sev = "Low"
        else:
            sev = "Low"
        out.append(
            Finding(
                id=Finding.make_id("native-recon", f"Missing {hdr}", base),
                source="native-recon",
                severity=sev,
                confidence="High",
                title=f"Missing security header: {hdr}",
                owasp_category="Security Misconfiguration",
                url=base,
                evidence=why[:300],
                remediation=f"Add `{hdr}` response header.",
                raw_ref="recon.json",
            )
        )
    return out


def from_zap_report(data: dict | list, raw_ref: str = "raw/zap.json") -> list[Finding]:
    """Parse ZAP baseline/full JSON report."""
    out: list[Finding] = []
    sites = data if isinstance(data, list) else data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if isinstance(alerts, dict):
            alerts = [alerts]
        for alert in alerts:
            name = alert.get("alert", alert.get("name", "ZAP alert"))
            risk = str(alert.get("riskcode", alert.get("risk", "0")))
            sev = ZAP_RISKCODE.get(risk, "Informational")
            insts = alert.get("instances", [])
            if isinstance(insts, dict):
                insts = [insts]
            url = insts[0].get("uri", site.get("@name", "")) if insts else site.get("@name", "")
            evidence = alert.get("desc", "")[:400]
            out.append(
                Finding(
                    id=Finding.make_id("zap", name, url),
                    source="zap",
                    severity=sev,
                    confidence="Medium",
                    title=name,
                    owasp_category=alert.get("pluginid", "ZAP"),
                    url=url,
                    evidence=evidence,
                    remediation=alert.get("solution", "Review ZAP guidance.")[:400],
                    raw_ref=raw_ref,
                )
            )
    return out


def from_nmap_xml(xml_text: str, raw_ref: str = "raw/nmap.xml") -> list[Finding]:
    import xml.etree.ElementTree as ET

    out: list[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr", "") if addr is not None else ""
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            pid = port.get("portid", "")
            svc = port.find("service")
            svc_name = svc.get("name", "") if svc is not None else ""
            title = f"Open port {pid}/{port.get('protocol','tcp')}"
            if svc_name:
                title += f" ({svc_name})"
            sev = "Informational" if pid in ("80", "443") else "Low"
            out.append(
                Finding(
                    id=Finding.make_id("nmap", title, ip),
                    source="nmap",
                    severity=sev,
                    confidence="High",
                    title=title,
                    owasp_category="Security Misconfiguration",
                    url=ip,
                    evidence=f"Service: {svc_name}",
                    remediation="Confirm only required ports are exposed.",
                    raw_ref=raw_ref,
                )
            )
        for script in host.findall(".//script"):
            sid = script.get("id", "")
            if "http" not in sid and "ssl" not in sid:
                continue
            out.append(
                Finding(
                    id=Finding.make_id("nmap", f"NSE: {sid}", ip),
                    source="nmap",
                    severity="Low",
                    confidence="Medium",
                    title=f"Nmap script {sid}",
                    owasp_category="Information Disclosure",
                    url=ip,
                    evidence=(script.get("output") or "")[:400],
                    remediation="Review Nmap script output.",
                    raw_ref=raw_ref,
                )
            )
    return out


def from_testssl_json(data: dict | list, raw_ref: str = "raw/testssl.json") -> list[Finding]:
    out: list[Finding] = []
    entries = data if isinstance(data, list) else data.get("scanResult", data.get("results", []))
    if not isinstance(entries, list):
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sev_raw = str(entry.get("severity", entry.get("level", "INFO"))).upper()
        sev = TESTSSL_SEVERITY.get(sev_raw, "Informational")
        if sev == "Informational" and sev_raw == "OK":
            continue
        title = entry.get("id", entry.get("finding", "TLS finding"))
        finding = entry.get("finding", entry.get("result", ""))
        out.append(
            Finding(
                id=Finding.make_id("testssl", str(title), ""),
                source="testssl",
                severity=sev,
                confidence="High",
                title=str(title),
                owasp_category="Cryptographic Failures",
                url="",
                evidence=str(finding)[:400],
                remediation="Harden TLS per testssl.sh recommendation.",
                raw_ref=raw_ref,
            )
        )
    return out


def from_browser_checks(checks: list[dict], raw_ref: str = "raw/browser.json") -> list[Finding]:
    out: list[Finding] = []
    for c in checks:
        out.append(
            Finding(
                id=Finding.make_id("browser", c.get("title", "browser"), c.get("url", "")),
                source="browser",
                severity=c.get("severity", "Low"),
                confidence=c.get("confidence", "Medium"),
                title=c.get("title", "Browser check"),
                owasp_category=c.get("category", "Client-side"),
                url=c.get("url", ""),
                evidence=c.get("evidence", "")[:400],
                remediation=c.get("remediation", "Review client-side behavior."),
                raw_ref=raw_ref,
            )
        )
    return out


def findings_to_json(findings: list[Finding]) -> list[dict]:
    return [f.to_dict() for f in findings]

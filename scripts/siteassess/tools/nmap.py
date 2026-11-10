"""Nmap via Docker — conservative web-oriented scan."""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from ..engagement import Engagement, require_authorization
from ..findings import Finding, StageCoverage, from_nmap_xml
from ..runner import docker_available

NMAP_IMAGE = "instrumentisto/nmap"


def _hostname(target_url: str) -> str:
    return urlparse(target_url).hostname or target_url


def run(engagement: Engagement, out_dir: Path, *, target_url: str) -> tuple[list[Finding], StageCoverage]:
    require_authorization(engagement, intrusive=True)
    ok, err = docker_available()
    if not ok:
        return [], StageCoverage("nmap", "skipped", err)

    host = _hostname(target_url)
    raw = out_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    xml_path = raw / "nmap.xml"
    docker = shutil.which("docker") or "docker"
    # Conservative: version + default scripts on top 100 ports.
    cmd = [
        docker, "run", "--rm", "--net=host",
        NMAP_IMAGE,
        "-sV", "-Pn", "--top-ports", "100", "-sC",
        "-oX", "/output/nmap.xml",
        host,
    ]
    # instrumentisto may not have /output - use mount
    wrk = raw.resolve()
    cmd = [
        docker, "run", "--rm",
        "-v", f"{wrk}:/output:rw",
        NMAP_IMAGE,
        "-sV", "-Pn", "--top-ports", "100", "-sC",
        "-oX", "/output/nmap.xml",
        host,
    ]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        elapsed = time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return [], StageCoverage("nmap", "failed", "timeout")

    if proc.returncode != 0 and not xml_path.exists():
        hint = (proc.stderr or proc.stdout or f"exit {proc.returncode}")[:300]
        return [], StageCoverage("nmap", "failed", hint)

    if not xml_path.exists():
        return [], StageCoverage("nmap", "failed", "no nmap.xml produced")

    xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
    findings = from_nmap_xml(xml_text)
    return findings, StageCoverage(
        "nmap", "ran", f"host={host}, exit={proc.returncode}, {elapsed:.0f}s", raw_path="raw/nmap.xml"
    )

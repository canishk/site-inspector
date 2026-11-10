"""testssl.sh via Docker."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from ..findings import Finding, StageCoverage, from_testssl_json
from ..runner import docker_available

TESTSSL_IMAGE = "drwetter/testssl.sh"


def _hostport(target_url: str) -> str:
    p = urlparse(target_url)
    if not p.hostname:
        return target_url
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.hostname}:{port}"


def run(out_dir: Path, *, target_url: str) -> tuple[list[Finding], StageCoverage]:
    ok, err = docker_available()
    if not ok:
        return [], StageCoverage("testssl", "skipped", err)

    hp = _hostport(target_url)
    raw = out_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    json_path = raw / "testssl.json"
    docker = shutil.which("docker") or "docker"
    cmd = [
        docker, "run", "--rm",
        "-v", f"{raw.resolve()}:/output:rw",
        TESTSSL_IMAGE,
        "--jsonfile-pretty", "/output/testssl.json",
        "--quiet",
        hp,
    ]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        elapsed = time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return [], StageCoverage("testssl", "failed", "timeout")

    data = None
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    if data is None:
        hint = (proc.stderr or proc.stdout or f"exit {proc.returncode}")[:300]
        return [], StageCoverage("testssl", "failed", hint)

    findings = from_testssl_json(data)
    status = "ran" if proc.returncode in (0, 1) else "failed"
    return findings, StageCoverage(
        "testssl", status, f"target={hp}, exit={proc.returncode}, {elapsed:.0f}s",
        raw_path="raw/testssl.json",
    )

"""OWASP ZAP via Docker (baseline / full)."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from ..engagement import Engagement, require_authorization
from ..findings import Finding, StageCoverage, from_zap_report
from ..runner import docker_available

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def _zap_docker_run(target_url: str, out_dir: Path, script: str, timeout_s: float) -> tuple[int, str, str, float]:
    ok, err = docker_available()
    if not ok:
        return -1, "", err, 0.0

    raw = out_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    report_name = "zap.json"
    docker = shutil.which("docker") or "docker"
    wrk = out_dir.resolve()
    cmd = [
        docker, "run", "--rm",
        "-v", f"{wrk}:/zap/wrk:rw",
        ZAP_IMAGE,
        script,
        "-t", target_url,
        "-J", report_name,
        "-m", "5",
    ]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        return proc.returncode, proc.stdout, proc.stderr, time.monotonic() - t0
    except subprocess.TimeoutExpired as e:
        stderr = (e.stderr or "timeout").decode() if isinstance(e.stderr, bytes) else (e.stderr or "timeout")
        return -9, "", stderr, time.monotonic() - t0


def run(
    engagement: Engagement,
    out_dir: Path,
    *,
    target_url: str,
    mode: str = "baseline",
) -> tuple[list[Finding], StageCoverage]:
    if mode == "full":
        require_authorization(engagement, intrusive=True)
        script = "zap-full-scan.py"
        timeout_s = 1200
    else:
        script = "zap-baseline.py"
        timeout_s = 600

    code, stdout, stderr, elapsed = _zap_docker_run(target_url, out_dir, script, timeout_s)
    report_path = out_dir / "zap.json"
    raw_copy = out_dir / "raw" / "zap.json"

    if code == -1 and stderr and "docker" in stderr.lower():
        return [], StageCoverage("zap", "skipped", stderr)

    data = None
    if report_path.exists():
        raw_copy.parent.mkdir(parents=True, exist_ok=True)
        raw_copy.write_bytes(report_path.read_bytes())
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    # ZAP baseline exits 1/2 when alerts found — still success for parsing.
    if data is None:
        detail = (stderr or stdout or f"exit {code}")[:300]
        return [], StageCoverage("zap", "failed", detail)

    findings = from_zap_report(data, raw_ref="raw/zap.json")
    status = "ran" if code in (0, 1, 2, 3) else "failed"
    return findings, StageCoverage(
        "zap", status, f"mode={mode}, exit={code}, {elapsed:.0f}s", raw_path="raw/zap.json"
    )

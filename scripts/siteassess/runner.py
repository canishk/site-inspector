"""Safe Docker container runner for scanner tools."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ContainerResult:
    image: str
    exit_code: int
    stdout: str
    stderr: str
    elapsed_s: float
    timed_out: bool = False
    error: str | None = None


def docker_available() -> tuple[bool, str]:
    exe = shutil.which("docker")
    if not exe:
        return False, "docker not found on PATH (install Docker Desktop)"
    try:
        r = subprocess.run(
            [exe, "info"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode != 0:
            return False, (r.stderr or "docker info failed").strip()[:200]
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "docker info timed out"
    except OSError as e:
        return False, str(e)


def run_container(
    image: str,
    container_args: list[str],
    *,
    out_dir: Path,
    timeout_s: float = 600,
    network: str = "bridge",
    memory: str = "2g",
    cpus: str = "2",
    pull: bool = True,
) -> ContainerResult:
    """Run `docker run --rm` with resource limits; capture stdout/stderr to out_dir/raw."""
    ok, err = docker_available()
    if not ok:
        return ContainerResult(image, -1, "", "", 0.0, error=err)

    raw = out_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    log_base = raw / f"docker_{int(time.time())}"
    stdout_path = log_base.with_suffix(".stdout.txt")
    stderr_path = log_base.with_suffix(".stderr.txt")

    docker = shutil.which("docker") or "docker"
    if pull:
        subprocess.run([docker, "pull", image], capture_output=True, timeout=300)

    cmd = [
        docker, "run", "--rm",
        "--network", network,
        "--memory", memory,
        "--cpus", cpus,
        "-v", f"{out_dir.resolve()}:/output:rw",
        image,
        *container_args,
    ]
    # Never log full cmd with secrets — container_args should be scope-only (URLs).
    meta_path = raw / "last_container_run.json"
    meta_path.write_text(
        json.dumps({"image": image, "args": container_args, "timeout_s": timeout_s}, indent=2),
        encoding="utf-8",
    )

    t0 = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        exit_code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        exit_code = -9
        stdout = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = (e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or "timed out")

    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
    elapsed = time.monotonic() - t0
    return ContainerResult(
        image=image,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_s=elapsed,
        timed_out=timed_out,
    )

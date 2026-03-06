"""
Egress enforcement for white_chek.

Supported modes:
  off          – no network restrictions (requires allow_off=True)
  enforced     – auto-select best backend: iptables on Linux,
                 docker on Windows, fail with clear error if unavailable
  iptables     – Linux native iptables (requires root)
  linux-netns  – Linux network namespace via iptables (requires root)
  docker       – Docker/Podman container backend (Windows or Linux)

EGRESS_BACKEND env var (or --egress-backend CLI flag):
  native       – use iptables directly (default on Linux)
  docker       – use Docker/Podman container proxy
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from typing import List, Optional


class EgressError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise EgressError(f"{' '.join(cmd)} failed: {res.stderr.strip()}")
    return res.stdout


def _check_iptables_available() -> bool:
    """Return True if iptables is present and executable."""
    return shutil.which("iptables") is not None


def _check_docker_available() -> bool:
    """Return True if docker (or podman) is present and the daemon is reachable."""
    docker_cmd = _docker_command()
    if docker_cmd is None:
        return False
    try:
        res = subprocess.run(
            [docker_cmd, "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return res.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _docker_command() -> Optional[str]:
    """Return 'docker' or 'podman' if either is in PATH, else None."""
    for cmd in ("docker", "podman"):
        if shutil.which(cmd):
            return cmd
    return None


# ---------------------------------------------------------------------------
# Iptables egress (Linux native)
# ---------------------------------------------------------------------------

@contextmanager
def _apply_iptables_egress(cidrs: List[str]):
    """Apply iptables OUTPUT whitelist and restore original rules on exit."""
    if not _check_iptables_available():
        raise EgressError(
            "iptables is not available on this system. "
            "Install iptables (e.g. 'apt-get install iptables') or run as root, "
            "or use --egress-backend docker / --egress-mode off --egress-allow-off."
        )

    with tempfile.NamedTemporaryFile("w+", suffix=".rules", delete=False) as backup:
        backup.write(_run(["iptables-save"]))
        backup.flush()
        backup_path = backup.name

    try:
        _run(["iptables", "-P", "OUTPUT", "DROP"])
        _run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        _run(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        for dns in ["8.8.8.8", "8.8.4.4", "1.1.1.1"]:
            _run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-d", dns, "-j", "ACCEPT"])
            _run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-d", dns, "-j", "ACCEPT"])
        for cidr in cidrs:
            _run(["iptables", "-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT"])
        yield
    finally:
        try:
            _run(["iptables-restore", backup_path])
        except EgressError:
            pass
        try:
            import os
            os.unlink(backup_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Docker egress backend
# ---------------------------------------------------------------------------

# Alpine-based image used for the container; must have iptables available.
_DOCKER_IMAGE = "alpine:3.19"
_CONTAINER_NAME = "white_chek_egress"

# Script run inside the container to set up iptables rules.
_SETUP_SCRIPT_TEMPLATE = """\
#!/bin/sh
set -e
apk add --no-cache iptables >/dev/null 2>&1 || true
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
{dns_rules}
{cidr_rules}
echo 'egress-ready'
tail -f /dev/null
"""


def _build_setup_script(cidrs: List[str]) -> str:
    dns_rules = "\n".join(
        f"iptables -A OUTPUT -p udp --dport 53 -d {dns} -j ACCEPT\n"
        f"iptables -A OUTPUT -p tcp --dport 53 -d {dns} -j ACCEPT"
        for dns in ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
    )
    cidr_rules = "\n".join(
        f"iptables -A OUTPUT -d {cidr} -j ACCEPT"
        for cidr in cidrs
    )
    return _SETUP_SCRIPT_TEMPLATE.format(
        dns_rules=dns_rules,
        cidr_rules=cidr_rules,
    )


@contextmanager
def _apply_docker_egress(cidrs: List[str]):
    """Start a Docker container with CIDR/DNS iptables rules and tear it down on exit."""
    docker_cmd = _docker_command()
    if docker_cmd is None:
        raise EgressError(
            "Docker (or Podman) is not installed. "
            "Install Docker to use egress on Windows, "
            "or use --egress-mode off --egress-allow-off."
        )
    if not _check_docker_available():
        raise EgressError(
            "Docker daemon is not running or not accessible. "
            "Start the Docker service and try again, "
            "or use --egress-mode off --egress-allow-off."
        )

    setup_script = _build_setup_script(cidrs)

    # Remove any stale container from a previous run
    subprocess.run(
        [docker_cmd, "rm", "-f", _CONTAINER_NAME],
        capture_output=True,
    )

    proc = None
    try:
        # Start container with NET_ADMIN capability so it can use iptables
        proc = subprocess.Popen(
            [
                docker_cmd, "run",
                "--rm",
                "--name", _CONTAINER_NAME,
                "--cap-add=NET_ADMIN",
                "--network=bridge",
                _DOCKER_IMAGE,
                "sh", "-c", setup_script,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait until the container signals it is ready
        import time
        ready = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert proc.stdout is not None
            line = proc.stdout.readline()
            if not line:
                break
            if "egress-ready" in line:
                ready = True
                break

        if not ready:
            stderr_out = ""
            if proc.stderr:
                stderr_out = proc.stderr.read(2000)
            raise EgressError(
                f"Docker egress container did not start in time. "
                f"stderr: {stderr_out.strip()}"
            )

        yield
    finally:
        # Stop container
        subprocess.run(
            [docker_cmd, "stop", _CONTAINER_NAME],
            capture_output=True,
            timeout=10,
        )
        if proc is not None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


# ---------------------------------------------------------------------------
# Auto-select best backend ("enforced" mode)
# ---------------------------------------------------------------------------

def _select_enforced_backend(egress_backend: str = "native") -> str:
    """Return the concrete mode to use for 'enforced'."""
    system = platform.system().lower()

    if egress_backend == "docker" or system == "windows":
        if not _check_docker_available():
            if system == "windows":
                raise EgressError(
                    "Egress mode is 'enforced' but Docker is not available on Windows. "
                    "Install Docker Desktop and ensure the daemon is running, "
                    "or use --egress-mode off --egress-allow-off to explicitly disable egress."
                )
            raise EgressError(
                "Egress backend 'docker' requested but Docker is not available. "
                "Install Docker or switch to --egress-backend native."
            )
        return "docker"

    # Linux (or other POSIX) with native iptables
    if system == "linux":
        if not _check_iptables_available():
            raise EgressError(
                "Egress mode is 'enforced' but iptables is not available. "
                "Install iptables (e.g. 'apt-get install iptables') or run as root. "
                "To disable egress explicitly use --egress-mode off --egress-allow-off."
            )
        return "iptables"

    raise EgressError(
        f"Egress mode is 'enforced' but no suitable backend found for OS '{platform.system()}'. "
        "Use --egress-backend docker (requires Docker) or "
        "--egress-mode off --egress-allow-off to disable egress."
    )


# ---------------------------------------------------------------------------
# Public context manager
# ---------------------------------------------------------------------------

@contextmanager
def apply_egress_whitelist(
    cidrs: List[str],
    mode: str = "enforced",
    egress_backend: str = "native",
    allow_off: bool = False,
):
    """Apply egress CIDR/DNS whitelist and restore on exit.

    Args:
        cidrs:           List of CIDR strings to allow outbound.
        mode:            One of 'off', 'enforced', 'iptables', 'linux-netns', 'docker'.
        egress_backend:  'native' or 'docker' (overrides auto-selection in 'enforced').
        allow_off:       Must be True when mode='off' to prevent accidental disabling.
    """
    if mode == "off":
        if not allow_off:
            raise EgressError(
                "Egress mode is 'off' but --egress-allow-off was not set. "
                "Pass --egress-allow-off (or set EGRESS_ALLOW_OFF=true) to confirm "
                "you intentionally want to disable egress enforcement."
            )
        yield
        return

    if mode == "enforced":
        mode = _select_enforced_backend(egress_backend)

    if mode == "iptables":
        with _apply_iptables_egress(cidrs):
            yield
        return

    if mode == "linux-netns":
        # Simplified: fall back to iptables in current namespace
        with _apply_iptables_egress(cidrs):
            yield
        return

    if mode == "docker":
        with _apply_docker_egress(cidrs):
            yield
        return

    raise EgressError(f"Unsupported egress mode: {mode!r}")

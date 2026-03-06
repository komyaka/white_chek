from __future__ import annotations
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

from ..normalize import normalize_key


@dataclass
class HysteriaResult:
    key: str
    uri: str
    latency_ms: float
    ok: bool
    reason: str | None = None


def ensure_binary(path: Optional[str] = None) -> str:
    candidate = path or os.environ.get("HYSTERIA_PATH") or "hysteria"
    if not os.path.isabs(candidate):
        resolved = shutil.which(candidate)
        if resolved is None:
            raise FileNotFoundError(f"Hysteria binary not found: {candidate}")
        return resolved
    if not os.path.exists(candidate):
        raise FileNotFoundError(f"Hysteria binary not found: {candidate}")
    return candidate


def _wait_for_port(port: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_single(
    uri: str,
    socks_port: int,
    timeout: float = 12,
    binary: Optional[str] = None,
    check_fn=None,
    startup_wait: float = 1.2,
    startup_poll: float = 0.2,
) -> HysteriaResult:
    key = normalize_key(uri)
    try:
        bin_path = ensure_binary(binary)
    except FileNotFoundError as e:
        return HysteriaResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason=str(e))

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "hy.yaml")
        with open(cfg_path, "w") as f:
            f.write(f"server: {uri}\nsocks5:\n  listen: 127.0.0.1:{socks_port}\n")

        proc = None
        try:
            proc = subprocess.Popen(
                [bin_path, "client", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ready = _wait_for_port(socks_port, timeout=startup_wait + 1.0)
            if not ready:
                return HysteriaResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason="hysteria SOCKS port not ready")

            if check_fn is not None:
                return check_fn(uri, key, socks_port, timeout)
            return HysteriaResult(key=key, uri=uri, latency_ms=1000.0, ok=True)
        except Exception as e:
            return HysteriaResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason=str(e))
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

from __future__ import annotations
import json
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
class XrayResult:
    key: str
    uri: str
    latency_ms: float
    ok: bool
    reason: str | None = None


def ensure_binary(path: Optional[str] = None) -> str:
    candidate = path or os.environ.get("XRAY_PATH") or "xray"
    if not os.path.isabs(candidate):
        resolved = shutil.which(candidate)
        if resolved is None:
            raise FileNotFoundError(f"Xray binary not found: {candidate}")
        return resolved
    if not os.path.exists(candidate):
        raise FileNotFoundError(f"Xray binary not found: {candidate}")
    return candidate


def build_config(uri: str, socks_port: int) -> dict:
    return {
        "inbounds": [
            {
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": []},
                "tag": "proxy",
            },
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


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
) -> XrayResult:
    key = normalize_key(uri)
    try:
        bin_path = ensure_binary(binary)
    except FileNotFoundError as e:
        return XrayResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason=str(e))

    cfg = build_config(uri, socks_port)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        f.flush()
        cfg_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [bin_path, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ready = _wait_for_port(socks_port, timeout=startup_wait + 1.0)
        if not ready:
            return XrayResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason="xray SOCKS port not ready")

        if check_fn is not None:
            return check_fn(uri, key, socks_port, timeout)
        return XrayResult(key=key, uri=uri, latency_ms=1000.0, ok=True)
    except Exception as e:
        return XrayResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason=str(e))
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

from __future__ import annotations
import json
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

from ..normalize import normalize_key

dataclass
class XrayResult:
    key: str
    uri: str
    latency_ms: float
    ok: bool
    reason: str | None = None


def ensure_binary(path: Optional[str] = None) -> str:
    return path or "xray"


def build_config(uri: str, socks_port: int) -> dict:
    # Minimal inbound + outbound
    return {
        "inbounds": [
            {"port": socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"}
        ],
    }


def run_single(uri: str, socks_port: int, timeout: float = 12, binary: Optional[str] = None) -> XrayResult:
    bin_path = ensure_binary(binary)
    cfg = build_config(uri, socks_port)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=True) as f:
        json.dump(cfg, f)
        f.flush()
        proc = subprocess.Popen([bin_path, "run", "-c", f.name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(timeout)
        proc.terminate()
    # Placeholder latency and ok result for now
    return XrayResult(key=normalize_key(uri), uri=uri, latency_ms=1000.0, ok=True)

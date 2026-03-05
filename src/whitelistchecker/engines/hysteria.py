from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from ..normalize import normalize_key

dataclass
class HysteriaResult:
    key: str
    uri: str
    latency_ms: float
    ok: bool
    reason: str | None = None


def ensure_binary(path: Optional[str] = None) -> str:
    return path or "hysteria"


def run_single(uri: str, socks_port: int, timeout: float = 12, binary: Optional[str] = None) -> HysteriaResult:
    # Placeholder stub; real implementation would spawn hysteria client
    return HysteriaResult(key=normalize_key(uri), uri=uri, latency_ms=1000.0, ok=True)

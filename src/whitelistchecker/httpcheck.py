from __future__ import annotations
import httpx
from typing import Tuple

class CheckResult:
    def __init__(self, ok: bool, latency_ms: float | None = None, reason: str | None = None):
        self.ok = ok
        self.latency_ms = latency_ms
        self.reason = reason


def check_urls_through_proxy(test_urls: list[str], proxies: dict, timeout: float, require_https: bool, verify_ssl: bool) -> Tuple[bool, float | None, str | None]:
    latencies = []
    for url in test_urls:
        try:
            with httpx.Client(proxies=proxies, timeout=timeout, verify=verify_ssl) as client:
                resp = client.get(url)
                resp.raise_for_status()
                latencies.append(resp.elapsed.total_seconds() * 1000)
        except Exception as e:
            return False, None, str(e)
    if require_https:
        # if HTTPS list is required ensure they were provided
        pass
    if latencies:
        return True, sum(latencies) / len(latencies), None
    return False, None, "no responses"

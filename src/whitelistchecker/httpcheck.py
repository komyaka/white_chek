from __future__ import annotations
import time
import httpx
from typing import List


class CheckResult:
    def __init__(self, ok: bool, latency_ms: float | None = None, reason: str | None = None):
        self.ok = ok
        self.latency_ms = latency_ms
        self.reason = reason


def check_urls_through_proxy(
    test_urls: List[str],
    socks_port: int,
    timeout: float,
    require_https: bool,
    verify_ssl: bool,
    requests_per_url: int = 2,
    min_successful_requests: int = 2,
    min_successful_urls: int = 2,
    max_response_time_ms: float = 3000.0,
) -> CheckResult:
    proxy_url = f"socks5://127.0.0.1:{socks_port}"
    proxies = {"http://": proxy_url, "https://": proxy_url}

    urls_ok = 0
    total_latencies: List[float] = []
    total_ok_requests = 0

    for url in test_urls:
        if require_https and not url.startswith("https://"):
            continue
        url_ok_count = 0
        for _ in range(requests_per_url):
            try:
                t0 = time.monotonic()
                with httpx.Client(proxies=proxies, timeout=timeout, verify=verify_ssl) as client:
                    resp = client.get(url)
                    resp.raise_for_status()
                elapsed_ms = (time.monotonic() - t0) * 1000
                if elapsed_ms > max_response_time_ms:
                    continue
                total_latencies.append(elapsed_ms)
                url_ok_count += 1
                total_ok_requests += 1
            except Exception:
                pass
        if url_ok_count >= min_successful_requests:
            urls_ok += 1

    if urls_ok < min_successful_urls:
        return CheckResult(
            ok=False,
            reason=f"only {urls_ok}/{min_successful_urls} URLs passed (need {min_successful_urls})",
        )
    if total_ok_requests < min_successful_requests:
        return CheckResult(
            ok=False,
            reason=f"only {total_ok_requests} successful requests",
        )
    avg_latency = sum(total_latencies) / len(total_latencies) if total_latencies else None
    return CheckResult(ok=True, latency_ms=avg_latency)


def strict_http_check(
    uri: str,
    key: str,
    socks_port: int,
    cfg,
) -> CheckResult:
    urls = list(cfg.test_urls_https) if cfg.require_https else list(cfg.test_urls)
    if not urls:
        urls = ["https://www.gstatic.com/generate_204"]

    attempts = cfg.strong_attempts if cfg.strong_style_test else 1
    timeout = cfg.strong_style_timeout if cfg.strong_style_test else cfg.connect_timeout
    max_rt = cfg.strong_max_response_time * 1000  # convert to ms

    best: CheckResult | None = None
    for _ in range(attempts):
        result = check_urls_through_proxy(
            test_urls=urls,
            socks_port=socks_port,
            timeout=timeout,
            require_https=cfg.require_https,
            verify_ssl=cfg.verify_https_ssl,
            requests_per_url=cfg.requests_per_url,
            min_successful_requests=cfg.min_successful_requests,
            min_successful_urls=cfg.min_successful_urls,
            max_response_time_ms=max_rt,
        )
        if result.ok:
            best = result
            break
        best = result

    if best is None:
        return CheckResult(ok=False, reason="no attempts made")

    if best.ok and best.latency_ms is not None and best.latency_ms > cfg.max_latency_ms:
        return CheckResult(ok=False, reason=f"latency {best.latency_ms:.0f}ms > {cfg.max_latency_ms}ms")

    return best

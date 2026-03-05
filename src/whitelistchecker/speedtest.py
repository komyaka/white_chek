from __future__ import annotations
import httpx
from typing import List, Tuple

class SpeedResult:
    def __init__(self, uri: str, metric: float, ok: bool, reason: str | None = None):
        self.uri = uri
        self.metric = metric
        self.ok = ok
        self.reason = reason


def run_speedtest(uris: List[str], cfg) -> List[SpeedResult]:
    results: List[SpeedResult] = []
    for uri in uris:
        # placeholder latency measurement via HEAD
        try:
            with httpx.Client(timeout=cfg.speed_test_timeout) as client:
                resp = client.head(cfg.speed_test_url)
                resp.raise_for_status()
                metric = resp.elapsed.total_seconds() * 1000
                ok = metric is not None and metric >= 0
                if ok and cfg.min_speed_threshold_mbps > 0:
                    # fake conversion
                    mbps = 8 * 250000 / (resp.elapsed.total_seconds() + 1e-3) / 1_000_000
                    if mbps < cfg.min_speed_threshold_mbps:
                        ok = False
                        results.append(SpeedResult(uri, mbps, False, "below threshold"))
                        continue
                results.append(SpeedResult(uri, metric, ok))
        except Exception as e:
            results.append(SpeedResult(uri, 0.0, False, str(e)))
    return results

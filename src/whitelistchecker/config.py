from __future__ import annotations
import argparse
import os
from dataclasses import dataclass, field
from typing import List


def str_to_bool(val: str) -> bool:
    return val.lower() in {"1", "true", "yes", "y", "on"}


def env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return str_to_bool(val)


def env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


@dataclass
class Config:
    mode: str = "merge"
    links_file: str = "links.txt"
    default_list_url: str | None = None
    output_dir: str = "configs"
    output_file: str = "white-list_available"
    test_urls: List[str] = field(default_factory=lambda: ["http://www.google.com/generate_204", "http://www.cloudflare.com/cdn-cgi/trace"])
    test_urls_https: List[str] = field(default_factory=lambda: ["https://www.gstatic.com/generate_204"])
    require_https: bool = True
    verify_https_ssl: bool = False
    strong_style_test: bool = True
    strong_style_timeout: int = 12
    strong_max_response_time: int = 3
    strong_double_check: bool = True
    strong_attempts: int = 3
    requests_per_url: int = 2
    min_successful_requests: int = 2
    min_successful_urls: int = 2
    request_delay: float = 0.1
    connect_timeout: int = 6
    connect_timeout_slow: int = 15
    max_response_time: int = 6
    max_latency_ms: int = 2000
    max_retries: int = 1
    retry_delay_base: float = 0.5
    retry_delay_multiplier: float = 2.0
    stability_checks: int = 2
    stability_check_delay: float = 2.0
    max_workers: int = 200
    base_port: int = 20000
    xray_startup_wait: float = 1.2
    xray_startup_poll_interval: float = 0.2
    xray_path: str | None = None
    hysteria_path: str | None = None
    egress_mode: str = "off"
    cidr_whitelist_url: str = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
    speed_test_enabled: bool = True
    speed_test_timeout: int = 2
    speed_test_mode: str = "latency"
    speed_test_metric: str = "latency"
    speed_test_requests: int = 5
    speed_test_url: str = "https://www.gstatic.com/generate_204"
    speed_test_workers: int = 200
    speed_test_download_timeout: int = 30
    speed_test_download_url_small: str = "https://speed.cloudflare.com/__down?bytes=250000"
    speed_test_download_url_medium: str = "https://speed.cloudflare.com/__down?bytes=1000000"
    min_speed_threshold_mbps: float = 2.5
    recheck_previous_whitelists: bool = True
    use_notworkers: bool = True
    speed_test_download_chunksize: int = 32768
    engine_mode: str = "real"  # real|stub

    cidr_whitelist_file: str | None = None
    keep_only_whitelist_files: bool = True


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Standalone whitelist checker")
    # ── Core ─────────────────────────────────────────────────────────────
    p.add_argument("--mode", choices=["merge", "single"], default=None)
    p.add_argument("--links-file")
    p.add_argument("--default-list-url")
    p.add_argument("--output-dir")
    p.add_argument("--output-file")
    p.add_argument("--cidr-whitelist-url")
    p.add_argument("--cidr-whitelist-file")
    p.add_argument("--egress-mode", choices=["off", "iptables", "linux-netns"])
    p.add_argument("--xray-path")
    p.add_argument("--hysteria-path")
    p.add_argument("--engine-mode", choices=["real", "stub"], dest="engine_mode")
    # ── Boolean flags ────────────────────────────────────────────────────
    p.add_argument("--speedtest", dest="speed_test_enabled", action="store_true")
    p.add_argument("--no-speedtest", dest="speed_test_enabled", action="store_false")
    p.add_argument("--recheck-previous", dest="recheck_previous_whitelists", action="store_true")
    p.add_argument("--no-recheck-previous", dest="recheck_previous_whitelists", action="store_false")
    p.add_argument("--use-notworkers", dest="use_notworkers", action="store_true")
    p.add_argument("--no-use-notworkers", dest="use_notworkers", action="store_false")
    p.add_argument("--require-https", dest="require_https", action="store_true")
    p.add_argument("--no-require-https", dest="require_https", action="store_false")
    p.add_argument("--verify-https-ssl", dest="verify_https_ssl", action="store_true")
    p.add_argument("--no-verify-https-ssl", dest="verify_https_ssl", action="store_false")
    p.add_argument("--strong-style-test", dest="strong_style_test", action="store_true")
    p.add_argument("--no-strong-style-test", dest="strong_style_test", action="store_false")
    p.add_argument("--strong-double-check", dest="strong_double_check", action="store_true")
    p.add_argument("--no-strong-double-check", dest="strong_double_check", action="store_false")
    p.add_argument("--keep-only-whitelist-files", dest="keep_only_whitelist_files", action="store_true")
    p.add_argument("--no-keep-only-whitelist-files", dest="keep_only_whitelist_files", action="store_false")
    # ── Workers / ports ──────────────────────────────────────────────────
    p.add_argument("--threads", dest="max_workers", type=int)
    p.add_argument("--base-port", dest="base_port", type=int)
    # ── HTTP check tuning ────────────────────────────────────────────────
    p.add_argument("--strong-style-timeout", type=int)
    p.add_argument("--strong-max-response-time", type=int)
    p.add_argument("--strong-attempts", type=int)
    p.add_argument("--requests-per-url", type=int)
    p.add_argument("--min-successful-requests", type=int)
    p.add_argument("--min-successful-urls", type=int)
    p.add_argument("--request-delay", type=float)
    p.add_argument("--connect-timeout", type=int)
    p.add_argument("--connect-timeout-slow", type=int)
    p.add_argument("--max-response-time", type=int)
    p.add_argument("--max-latency-ms", type=int)
    p.add_argument("--max-retries", type=int)
    p.add_argument("--retry-delay-base", type=float)
    p.add_argument("--retry-delay-multiplier", type=float)
    p.add_argument("--stability-checks", type=int)
    p.add_argument("--stability-check-delay", type=float)
    # ── Engine startup ───────────────────────────────────────────────────
    p.add_argument("--xray-startup-wait", type=float)
    p.add_argument("--xray-startup-poll-interval", type=float)
    # ── Speedtest tuning ─────────────────────────────────────────────────
    p.add_argument("--speed-test-timeout", type=int)
    p.add_argument("--speed-test-mode")
    p.add_argument("--speed-test-metric")
    p.add_argument("--speed-test-requests", type=int)
    p.add_argument("--speed-test-url")
    p.add_argument("--speed-test-workers", type=int)
    p.add_argument("--speed-test-download-timeout", type=int)
    p.add_argument("--speed-test-download-url-small")
    p.add_argument("--speed-test-download-url-medium")
    p.add_argument("--min-speed-threshold-mbps", type=float)
    p.add_argument("--speed-test-download-chunksize", type=int)
    # ── Test URLs (comma-separated) ──────────────────────────────────────
    p.add_argument("--test-urls", help="comma-separated list of HTTP test URLs")
    p.add_argument("--test-urls-https", help="comma-separated list of HTTPS test URLs")
    # Reset boolean flag defaults to None so we can distinguish
    # "not specified" from an explicit --flag / --no-flag.
    p.set_defaults(
        speed_test_enabled=None,
        recheck_previous_whitelists=None,
        use_notworkers=None,
        require_https=None,
        verify_https_ssl=None,
        strong_style_test=None,
        strong_double_check=None,
        keep_only_whitelist_files=None,
    )
    return p


def _first(*values):
    """Return the first non-None value, or None if all are None."""
    for v in values:
        if v is not None:
            return v
    return None


def _first_bool(cli_val, env_name: str, default: bool) -> bool:
    """CLI flag → env var → default for boolean options."""
    if cli_val is not None:
        return cli_val
    return env_bool(env_name, default)


def _first_int(cli_val, env_name: str, default: int) -> int:
    """CLI flag → env var → default for int options."""
    if cli_val is not None:
        return cli_val
    return env_int(env_name, default)


def _first_float(cli_val, env_name: str, default: float) -> float:
    """CLI flag → env var → default for float options."""
    if cli_val is not None:
        return cli_val
    raw = env(env_name)
    if raw is not None:
        try:
            return float(raw)
        except ValueError:
            pass
    return default


def _first_str(cli_val, env_name: str, default: str | None) -> str | None:
    """CLI flag → env var → default for string options."""
    if cli_val is not None:
        return cli_val
    return env(env_name, default)


def load_config(args: list[str] | None = None) -> Config:
    parser = build_arg_parser()
    ns = parser.parse_args(args=args)

    cfg = Config()

    # ── Core ─────────────────────────────────────────────────────────────
    cfg.mode = _first_str(ns.mode, "MODE", cfg.mode)
    cfg.links_file = _first_str(ns.links_file, "LINKS_FILE", cfg.links_file)
    cfg.default_list_url = _first_str(ns.default_list_url, "DEFAULT_LIST_URL", cfg.default_list_url)
    cfg.output_dir = _first_str(ns.output_dir, "OUTPUT_DIR", cfg.output_dir)
    cfg.output_file = _first_str(ns.output_file, "OUTPUT_FILE", cfg.output_file)
    cfg.cidr_whitelist_url = _first_str(ns.cidr_whitelist_url, "CIDR_WHITELIST_URL", cfg.cidr_whitelist_url)
    cfg.cidr_whitelist_file = _first_str(ns.cidr_whitelist_file, "CIDR_WHITELIST_FILE", cfg.cidr_whitelist_file)
    cfg.egress_mode = _first_str(ns.egress_mode, "EGRESS_MODE", cfg.egress_mode)
    cfg.xray_path = _first_str(ns.xray_path, "XRAY_PATH", cfg.xray_path)
    cfg.hysteria_path = _first_str(ns.hysteria_path, "HYSTERIA_PATH", cfg.hysteria_path)
    cfg.engine_mode = _first_str(ns.engine_mode, "ENGINE_MODE", cfg.engine_mode)

    # ── Boolean flags ────────────────────────────────────────────────────
    cfg.speed_test_enabled = _first_bool(ns.speed_test_enabled, "SPEED_TEST_ENABLED", cfg.speed_test_enabled)
    cfg.recheck_previous_whitelists = _first_bool(ns.recheck_previous_whitelists, "RECHECK_PREVIOUS_WHITELISTS", cfg.recheck_previous_whitelists)
    cfg.use_notworkers = _first_bool(ns.use_notworkers, "USE_NOTWORKERS", cfg.use_notworkers)
    cfg.require_https = _first_bool(ns.require_https, "REQUIRE_HTTPS", cfg.require_https)
    cfg.verify_https_ssl = _first_bool(ns.verify_https_ssl, "VERIFY_HTTPS_SSL", cfg.verify_https_ssl)
    cfg.strong_style_test = _first_bool(ns.strong_style_test, "STRONG_STYLE_TEST", cfg.strong_style_test)
    cfg.strong_double_check = _first_bool(ns.strong_double_check, "STRONG_DOUBLE_CHECK", cfg.strong_double_check)
    cfg.keep_only_whitelist_files = _first_bool(ns.keep_only_whitelist_files, "KEEP_ONLY_WHITELIST_FILES", cfg.keep_only_whitelist_files)

    # ── Workers / ports ──────────────────────────────────────────────────
    cfg.max_workers = _first_int(ns.max_workers, "MAX_WORKERS", cfg.max_workers)
    cfg.base_port = _first_int(ns.base_port, "BASE_PORT", cfg.base_port)

    # ── HTTP check tuning ────────────────────────────────────────────────
    cfg.strong_style_timeout = _first_int(ns.strong_style_timeout, "STRONG_STYLE_TIMEOUT", cfg.strong_style_timeout)
    cfg.strong_max_response_time = _first_int(ns.strong_max_response_time, "STRONG_MAX_RESPONSE_TIME", cfg.strong_max_response_time)
    cfg.strong_attempts = _first_int(ns.strong_attempts, "STRONG_ATTEMPTS", cfg.strong_attempts)
    cfg.requests_per_url = _first_int(ns.requests_per_url, "REQUESTS_PER_URL", cfg.requests_per_url)
    cfg.min_successful_requests = _first_int(ns.min_successful_requests, "MIN_SUCCESSFUL_REQUESTS", cfg.min_successful_requests)
    cfg.min_successful_urls = _first_int(ns.min_successful_urls, "MIN_SUCCESSFUL_URLS", cfg.min_successful_urls)
    cfg.request_delay = _first_float(ns.request_delay, "REQUEST_DELAY", cfg.request_delay)
    cfg.connect_timeout = _first_int(ns.connect_timeout, "CONNECT_TIMEOUT", cfg.connect_timeout)
    cfg.connect_timeout_slow = _first_int(ns.connect_timeout_slow, "CONNECT_TIMEOUT_SLOW", cfg.connect_timeout_slow)
    cfg.max_response_time = _first_int(ns.max_response_time, "MAX_RESPONSE_TIME", cfg.max_response_time)
    cfg.max_latency_ms = _first_int(ns.max_latency_ms, "MAX_LATENCY_MS", cfg.max_latency_ms)
    cfg.max_retries = _first_int(ns.max_retries, "MAX_RETRIES", cfg.max_retries)
    cfg.retry_delay_base = _first_float(ns.retry_delay_base, "RETRY_DELAY_BASE", cfg.retry_delay_base)
    cfg.retry_delay_multiplier = _first_float(ns.retry_delay_multiplier, "RETRY_DELAY_MULTIPLIER", cfg.retry_delay_multiplier)
    cfg.stability_checks = _first_int(ns.stability_checks, "STABILITY_CHECKS", cfg.stability_checks)
    cfg.stability_check_delay = _first_float(ns.stability_check_delay, "STABILITY_CHECK_DELAY", cfg.stability_check_delay)

    # ── Engine startup ───────────────────────────────────────────────────
    cfg.xray_startup_wait = _first_float(ns.xray_startup_wait, "XRAY_STARTUP_WAIT", cfg.xray_startup_wait)
    cfg.xray_startup_poll_interval = _first_float(ns.xray_startup_poll_interval, "XRAY_STARTUP_POLL_INTERVAL", cfg.xray_startup_poll_interval)

    # ── Speedtest tuning ─────────────────────────────────────────────────
    cfg.speed_test_timeout = _first_int(ns.speed_test_timeout, "SPEED_TEST_TIMEOUT", cfg.speed_test_timeout)
    cfg.speed_test_mode = _first_str(ns.speed_test_mode, "SPEED_TEST_MODE", cfg.speed_test_mode)
    cfg.speed_test_metric = _first_str(ns.speed_test_metric, "SPEED_TEST_METRIC", cfg.speed_test_metric)
    cfg.speed_test_requests = _first_int(ns.speed_test_requests, "SPEED_TEST_REQUESTS", cfg.speed_test_requests)
    cfg.speed_test_url = _first_str(ns.speed_test_url, "SPEED_TEST_URL", cfg.speed_test_url)
    cfg.speed_test_workers = _first_int(ns.speed_test_workers, "SPEED_TEST_WORKERS", cfg.speed_test_workers)
    cfg.speed_test_download_timeout = _first_int(ns.speed_test_download_timeout, "SPEED_TEST_DOWNLOAD_TIMEOUT", cfg.speed_test_download_timeout)
    cfg.speed_test_download_url_small = _first_str(ns.speed_test_download_url_small, "SPEED_TEST_DOWNLOAD_URL_SMALL", cfg.speed_test_download_url_small)
    cfg.speed_test_download_url_medium = _first_str(ns.speed_test_download_url_medium, "SPEED_TEST_DOWNLOAD_URL_MEDIUM", cfg.speed_test_download_url_medium)
    cfg.min_speed_threshold_mbps = _first_float(ns.min_speed_threshold_mbps, "MIN_SPEED_THRESHOLD_MBPS", cfg.min_speed_threshold_mbps)
    cfg.speed_test_download_chunksize = _first_int(ns.speed_test_download_chunksize, "SPEED_TEST_DOWNLOAD_CHUNKSIZE", cfg.speed_test_download_chunksize)

    # ── Test URLs (CLI comma-separated → env comma-separated → default) ─
    if ns.test_urls:
        cfg.test_urls = [u for u in ns.test_urls.split(",") if u]
    else:
        env_test_urls = env("TEST_URLS")
        if env_test_urls:
            cfg.test_urls = [u for u in env_test_urls.split(",") if u]

    if ns.test_urls_https:
        cfg.test_urls_https = [u for u in ns.test_urls_https.split(",") if u]
    else:
        env_test_urls_https = env("TEST_URLS_HTTPS")
        if env_test_urls_https:
            cfg.test_urls_https = [u for u in env_test_urls_https.split(",") if u]

    return cfg

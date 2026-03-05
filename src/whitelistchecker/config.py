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
    egress_mode: str = "iptables"
    cidr_whitelist_url: str = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
    speed_test_enabled: bool = False
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


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Standalone whitelist checker")
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
    p.add_argument("--speedtest", dest="speed_test_enabled", action="store_true")
    p.add_argument("--no-speedtest", dest="speed_test_enabled", action="store_false")
    p.add_argument("--recheck-previous", dest="recheck_previous_whitelists", action="store_true")
    p.add_argument("--no-recheck-previous", dest="recheck_previous_whitelists", action="store_false")
    p.add_argument("--use-notworkers", dest="use_notworkers", action="store_true")
    p.add_argument("--no-use-notworkers", dest="use_notworkers", action="store_false")
    p.add_argument("--threads", dest="max_workers", type=int)
    p.add_argument("--base-port", dest="base_port", type=int)
    p.add_argument("--engine-mode", choices=["real", "stub"], dest="engine_mode")
    return p


def load_config(args: list[str] | None = None) -> Config:
    parser = build_arg_parser()
    ns = parser.parse_args(args=args)

    cfg = Config()

    cfg.mode = ns.mode or env("MODE", cfg.mode)
    cfg.links_file = ns.links_file or env("LINKS_FILE", cfg.links_file)
    cfg.default_list_url = ns.default_list_url or env("DEFAULT_LIST_URL", cfg.default_list_url)
    cfg.output_dir = ns.output_dir or env("OUTPUT_DIR", cfg.output_dir)
    cfg.output_file = ns.output_file or env("OUTPUT_FILE", cfg.output_file)

    if ns.cidr_whitelist_url:
        cfg.cidr_whitelist_url = ns.cidr_whitelist_url
    else:
        cfg.cidr_whitelist_url = env("CIDR_WHITELIST_URL", cfg.cidr_whitelist_url)

    cfg.cidr_whitelist_file = ns.cidr_whitelist_file or env("CIDR_WHITELIST_FILE")
    cfg.egress_mode = ns.egress_mode or env("EGRESS_MODE", cfg.egress_mode)
    cfg.xray_path = ns.xray_path or env("XRAY_PATH")
    cfg.hysteria_path = ns.hysteria_path or env("HYSTERIA_PATH")

    if ns.speed_test_enabled is not None:
        cfg.speed_test_enabled = ns.speed_test_enabled
    else:
        cfg.speed_test_enabled = env_bool("SPEED_TEST_ENABLED", cfg.speed_test_enabled)

    cfg.speed_test_timeout = env_int("SPEED_TEST_TIMEOUT", cfg.speed_test_timeout)
    cfg.speed_test_mode = env("SPEED_TEST_MODE", cfg.speed_test_mode)
    cfg.speed_test_metric = env("SPEED_TEST_METRIC", cfg.speed_test_metric)
    cfg.speed_test_requests = env_int("SPEED_TEST_REQUESTS", cfg.speed_test_requests)
    cfg.speed_test_url = env("SPEED_TEST_URL", cfg.speed_test_url)
    cfg.speed_test_workers = env_int("SPEED_TEST_WORKERS", cfg.speed_test_workers)
    cfg.speed_test_download_timeout = env_int("SPEED_TEST_DOWNLOAD_TIMEOUT", cfg.speed_test_download_timeout)
    cfg.speed_test_download_url_small = env("SPEED_TEST_DOWNLOAD_URL_SMALL", cfg.speed_test_download_url_small)
    cfg.speed_test_download_url_medium = env("SPEED_TEST_DOWNLOAD_URL_MEDIUM", cfg.speed_test_download_url_medium)
    cfg.min_speed_threshold_mbps = float(env("MIN_SPEED_THRESHOLD_MBPS", str(cfg.min_speed_threshold_mbps)))

    cfg.require_https = env_bool("REQUIRE_HTTPS", cfg.require_https)
    cfg.verify_https_ssl = env_bool("VERIFY_HTTPS_SSL", cfg.verify_https_ssl)
    cfg.strong_style_test = env_bool("STRONG_STYLE_TEST", cfg.strong_style_test)
    cfg.strong_style_timeout = env_int("STRONG_STYLE_TIMEOUT", cfg.strong_style_timeout)
    cfg.strong_max_response_time = env_int("STRONG_MAX_RESPONSE_TIME", cfg.strong_max_response_time)
    cfg.strong_double_check = env_bool("STRONG_DOUBLE_CHECK", cfg.strong_double_check)
    cfg.strong_attempts = env_int("STRONG_ATTEMPTS", cfg.strong_attempts)
    cfg.requests_per_url = env_int("REQUESTS_PER_URL", cfg.requests_per_url)
    cfg.min_successful_requests = env_int("MIN_SUCCESSFUL_REQUESTS", cfg.min_successful_requests)
    cfg.min_successful_urls = env_int("MIN_SUCCESSFUL_URLS", cfg.min_successful_urls)
    cfg.request_delay = float(env("REQUEST_DELAY", str(cfg.request_delay)))
    cfg.connect_timeout = env_int("CONNECT_TIMEOUT", cfg.connect_timeout)
    cfg.connect_timeout_slow = env_int("CONNECT_TIMEOUT_SLOW", cfg.connect_timeout_slow)
    cfg.max_response_time = env_int("MAX_RESPONSE_TIME", cfg.max_response_time)
    cfg.max_latency_ms = env_int("MAX_LATENCY_MS", cfg.max_latency_ms)
    cfg.max_retries = env_int("MAX_RETRIES", cfg.max_retries)
    cfg.retry_delay_base = float(env("RETRY_DELAY_BASE", str(cfg.retry_delay_base)))
    cfg.retry_delay_multiplier = float(env("RETRY_DELAY_MULTIPLIER", str(cfg.retry_delay_multiplier)))
    cfg.stability_checks = env_int("STABILITY_CHECKS", cfg.stability_checks)
    cfg.stability_check_delay = float(env("STABILITY_CHECK_DELAY", str(cfg.stability_check_delay)))
    cfg.max_workers = ns.max_workers or env_int("MAX_WORKERS", cfg.max_workers)
    cfg.base_port = ns.base_port or env_int("BASE_PORT", cfg.base_port)
    cfg.xray_startup_wait = float(env("XRAY_STARTUP_WAIT", str(cfg.xray_startup_wait)))
    cfg.xray_startup_poll_interval = float(env("XRAY_STARTUP_POLL_INTERVAL", str(cfg.xray_startup_poll_interval)))

    cfg.recheck_previous_whitelists = cfg.recheck_previous_whitelists if ns.recheck_previous_whitelists is None else ns.recheck_previous_whitelists
    cfg.recheck_previous_whitelists = env_bool("RECHECK_PREVIOUS_WHITELISTS", cfg.recheck_previous_whitelists)

    cfg.use_notworkers = cfg.use_notworkers if ns.use_notworkers is None else ns.use_notworkers
    cfg.use_notworkers = env_bool("USE_NOTWORKERS", cfg.use_notworkers)

    cfg.engine_mode = ns.engine_mode or env("ENGINE_MODE", cfg.engine_mode)

    # split lists from env if provided
    env_test_urls = env("TEST_URLS")
    if env_test_urls:
        cfg.test_urls = [u for u in env_test_urls.split(",") if u]
    env_test_urls_https = env("TEST_URLS_HTTPS")
    if env_test_urls_https:
        cfg.test_urls_https = [u for u in env_test_urls_https.split(",") if u]

    return cfg

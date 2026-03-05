from __future__ import annotations
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from .config import load_config
from .sources import load_source_urls, merge_sources
from .cidr import fetch_cidr_list
from .egress import apply_egress_whitelist
from .normalize import normalize_key
from .stats import compute_source_stats, write_source_stats
from .cleanup import cleanup_output_dir
from .outputs import write_available
from .speedtest import run_speedtest
from .httpcheck import strict_http_check

console = Console()

# Stub allowlist key prefix (keys starting with these are "approved" in stub mode)
STUB_OK_PREFIX = "vless://"


def _run_checks_stub(pool: List[str], cfg, base_port: int):
    """Stub engine: mark everything as OK (for testing)."""
    from .engines.xray import XrayResult
    results = []
    for i, uri in enumerate(pool):
        key = normalize_key(uri)
        results.append(XrayResult(key=key, uri=uri, latency_ms=float(100 + i), ok=True))
    return results


def _check_single_xray(uri: str, port: int, cfg):
    from .engines.xray import XrayResult, run_single
    from .httpcheck import strict_http_check

    key = normalize_key(uri)

    def check_fn(u, k, p, timeout):
        cr = strict_http_check(u, k, p, cfg)
        return XrayResult(key=k, uri=u, latency_ms=cr.latency_ms or 0.0, ok=cr.ok, reason=cr.reason)

    return run_single(
        uri=uri,
        socks_port=port,
        timeout=cfg.strong_style_timeout,
        binary=cfg.xray_path,
        check_fn=check_fn,
        startup_wait=cfg.xray_startup_wait,
        startup_poll=cfg.xray_startup_poll_interval,
    )


def _check_single_hysteria(uri: str, port: int, cfg):
    from .engines.hysteria import HysteriaResult, run_single
    from .httpcheck import strict_http_check

    key = normalize_key(uri)

    def check_fn(u, k, p, timeout):
        cr = strict_http_check(u, k, p, cfg)
        return HysteriaResult(key=k, uri=u, latency_ms=cr.latency_ms or 0.0, ok=cr.ok, reason=cr.reason)

    return run_single(
        uri=uri,
        socks_port=port,
        timeout=cfg.strong_style_timeout,
        binary=cfg.hysteria_path,
        check_fn=check_fn,
        startup_wait=cfg.xray_startup_wait,
        startup_poll=cfg.xray_startup_poll_interval,
    )


def _run_checks_real(pool: List[str], cfg, base_port: int, label: str = "check"):
    results = []
    xray_pool = [u for u in pool if u.startswith(("vless://", "vmess://", "trojan://", "ss://"))]
    hyst_pool = [u for u in pool if u.startswith(("hysteria://", "hysteria2://", "hy2://"))]
    total = len(xray_pool) + len(hyst_pool)

    processed = 0
    ok_count = 0
    fail_count = 0
    start = time.monotonic()
    lock = threading.Lock()
    last_print = [time.monotonic()]

    def _progress():
        with lock:
            elapsed = time.monotonic() - start
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (total - processed) / rate if rate > 0 else 0
            console.print(
                f"[cyan]{label}[/cyan] {processed}/{total} ok={ok_count} fail={fail_count} "
                f"rate={rate:.1f}/s eta={eta:.0f}s"
            )
            last_print[0] = time.monotonic()

    def _maybe_print():
        if time.monotonic() - last_print[0] >= 5:
            _progress()

    port_counter = [base_port]

    def _alloc_port():
        with lock:
            p = port_counter[0]
            port_counter[0] += 1
            return p

    def _xray_task(uri):
        nonlocal processed, ok_count, fail_count
        port = _alloc_port()
        r = _check_single_xray(uri, port, cfg)
        with lock:
            processed += 1
            if r.ok:
                ok_count += 1
            else:
                fail_count += 1
        _maybe_print()
        return r

    def _hyst_task(uri):
        nonlocal processed, ok_count, fail_count
        port = _alloc_port()
        r = _check_single_hysteria(uri, port, cfg)
        with lock:
            processed += 1
            if r.ok:
                ok_count += 1
            else:
                fail_count += 1
        _maybe_print()
        return r

    workers = min(cfg.max_workers, max(1, total))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for uri in xray_pool:
            futures[ex.submit(_xray_task, uri)] = uri
        for uri in hyst_pool:
            futures[ex.submit(_hyst_task, uri)] = uri

        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                uri = futures[fut]
                key = normalize_key(uri)
                if uri.startswith(("hysteria://", "hysteria2://", "hy2://")):
                    from .engines.hysteria import HysteriaResult
                    results.append(HysteriaResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason=str(e)))
                else:
                    from .engines.xray import XrayResult
                    results.append(XrayResult(key=key, uri=uri, latency_ms=0.0, ok=False, reason=str(e)))

    _progress()
    return results


def main(argv=None):
    cfg = load_config(argv)
    console.print("[bold cyan]Whitelist checker starting[/bold cyan]")
    # Print effective config (redacted secrets — none here)
    console.print(cfg)

    # --- Load & merge sources ---
    urls = load_source_urls(cfg.links_file)
    console.print(f"[blue]Loading {len(urls)} source URLs...[/blue]")
    def _merge_progress(i, total, url, unique, new, error=None):
        if error:
            console.print(f"[red]  {i}/{total} {url} — ERROR: {error}[/red]")
        else:
            console.print(f"[blue]  {i}/{total} {url} — {unique} unique, {new} new[/blue]")
    global_pool, source_map = merge_sources(urls, progress_fn=_merge_progress)
    console.print(f"[blue]Merged pool: {len(global_pool)} unique keys[/blue]")

    # --- Recheck previous whitelist ---
    if cfg.recheck_previous_whitelists:
        prev_path = Path(cfg.output_dir) / cfg.output_file
        if prev_path.exists():
            prev_keys_seen = {normalize_key(x) for x in global_pool}
            added = 0
            for line in prev_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                key = normalize_key(line)
                if key not in prev_keys_seen:
                    global_pool.append(line)
                    prev_keys_seen.add(key)
                    added += 1
            if added:
                console.print(f"[blue]Recheck: added {added} keys from previous whitelist[/blue]")

    # --- Notworkers exclusion ---
    nw_path = Path(cfg.output_dir) / "notworkers"
    if cfg.use_notworkers and nw_path.exists():
        blocked = {normalize_key(x) for x in nw_path.read_text(encoding="utf-8").splitlines() if x.strip()}
        before = len(global_pool)
        global_pool = [line for line in global_pool if normalize_key(line) not in blocked]
        console.print(f"[blue]Notworkers: excluded {before - len(global_pool)} keys[/blue]")

    # --- Egress ---
    cidrs = []
    if cfg.egress_mode != "off":
        console.print(f"[yellow]Applying egress whitelist (mode={cfg.egress_mode})...[/yellow]")
        if cfg.cidr_whitelist_file and Path(cfg.cidr_whitelist_file).exists():
            cidrs = [ln.strip() for ln in Path(cfg.cidr_whitelist_file).read_text().splitlines() if ln.strip()]
        else:
            cidrs = fetch_cidr_list(cfg.cidr_whitelist_url)
        console.print(f"[blue]{len(cidrs)} CIDRs loaded[/blue]")

    # --- Engine checks ---
    with apply_egress_whitelist(cidrs, mode=cfg.egress_mode):
        if cfg.engine_mode == "stub":
            console.print("[yellow]Engine mode: stub (all keys marked OK)[/yellow]")
            ok_results = _run_checks_stub(global_pool, cfg, cfg.base_port)
        else:
            console.print(f"[blue]Checking {len(global_pool)} proxies with {cfg.max_workers} workers...[/blue]")
            ok_results = _run_checks_real(global_pool, cfg, cfg.base_port)

    # --- Notworkers append for failing keys ---
    if cfg.use_notworkers:
        failing = [r for r in ok_results if not r.ok]
        if failing:
            nw_path.parent.mkdir(parents=True, exist_ok=True)
            existing_nw: set = set()
            if nw_path.exists():
                existing_nw = {normalize_key(ln) for ln in nw_path.read_text(encoding="utf-8").splitlines() if ln.strip()}
            new_failing = [r.uri for r in failing if normalize_key(r.uri) not in existing_nw]
            if new_failing:
                with nw_path.open("a", encoding="utf-8") as f:
                    for uri in new_failing:
                        f.write(uri + "\n")
                console.print(f"[yellow]Appended {len(new_failing)} failing keys to notworkers[/yellow]")

    # --- Write available outputs ---
    out_base = cfg.output_file  # e.g. "white-list_available"
    path_available, path_top = write_available(ok_results, cfg.output_dir, out_base)
    console.print(f"[green]Written {path_available} ({sum(1 for r in ok_results if r.ok)} working)[/green]")

    # --- Speedtest ---
    if cfg.speed_test_enabled:
        console.print(f"[blue]Running speedtest (mode={cfg.speed_test_mode})...[/blue]")
        working_uris = [r.uri for r in ok_results if r.ok]
        st_results = run_speedtest(working_uris, cfg)
        st_ok = [r for r in st_results if r.ok]
        write_available(st_ok, cfg.output_dir, f"{out_base}_st")
        console.print(f"[green]Speedtest: {len(st_ok)}/{len(working_uris)} passed[/green]")
    else:
        # Produce _st files as copies to keep 5-file contract
        write_available([r for r in ok_results if r.ok], cfg.output_dir, f"{out_base}_st")

    # --- Source stats ---
    rows = compute_source_stats(source_map, path_available)
    write_source_stats(rows, cfg.output_dir)

    # --- Cleanup ---
    cleanup_output_dir(cfg.output_dir, keep_only_whitelist_files=cfg.keep_only_whitelist_files)

    console.print("[bold green]Done[/bold green]")


if __name__ == "__main__":
    main()

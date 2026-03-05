from __future__ import annotations
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from .config import load_config
from .sources import load_source_urls, merge_sources
from .cidr import fetch_cidr_list
from .egress import apply_egress_whitelist
from .normalize import normalize_key
from .stats import compute_source_stats, write_source_stats
from .cleanup import cleanup_output_dir
from .outputs import write_available
from .speedtest import run_speedtest

console = Console()


def main(argv=None):
    cfg = load_config(argv)
    console.print("[bold cyan]Whitelist checker starting[/bold cyan]")
    console.print(cfg)

    urls = load_source_urls(cfg.links_file)
    global_pool, source_map = merge_sources(urls)

    # recheck previous
    if cfg.recheck_previous_whitelists:
        prev_path = Path(cfg.output_dir) / cfg.output_file
        if prev_path.exists():
            for line in prev_path.read_text(encoding="utf-8").splitlines():
                key = normalize_key(line)
                if key not in {normalize_key(x) for x in global_pool}:
                    global_pool.append(line)

    # notworkers exclude
    if cfg.use_notworkers:
        nw_path = Path(cfg.output_dir) / "notworkers"
        if nw_path.exists():
            blocked = {normalize_key(x) for x in nw_path.read_text(encoding="utf-8").splitlines() if x.strip()}
            global_pool = [line for line in global_pool if normalize_key(line) not in blocked]

    # split pools
    xray_pool = [u for u in global_pool if u.startswith(("vless://", "vmess://", "trojan://", "ss://"))]
    hyst_pool = [u for u in global_pool if u.startswith(("hysteria://", "hysteria2://", "hy2://"))]

    # egress
    cidrs = []
    if cfg.egress_mode != "off":
        if cfg.cidr_whitelist_file and Path(cfg.cidr_whitelist_file).exists():
            cidrs = [line.strip() for line in Path(cfg.cidr_whitelist_file).read_text().splitlines() if line.strip()]
        else:
            cidrs = fetch_cidr_list(cfg.cidr_whitelist_url)

    with apply_egress_whitelist(cidrs, mode=cfg.egress_mode):
        # TODO: real checks; placeholder ok results
        from .engines.xray import XrayResult
        ok_results = [XrayResult(normalize_key(u), u, 1000.0, True) for u in xray_pool]
        from .engines.hysteria import HysteriaResult
        ok_results += [HysteriaResult(normalize_key(u), u, 1000.0, True) for u in hyst_pool]

    path_available, path_top = write_available(ok_results, cfg.output_dir, cfg.output_file)

    # speedtest
    st_results = []
    if cfg.speed_test_enabled:
        st_results = run_speedtest([r.uri for r in ok_results if r.ok], cfg)
        st_ok = [r for r in st_results if r.ok]
        write_available(st_ok, cfg.output_dir, f"{cfg.output_file}_st")
    else:
        # create empty st files for compliance
        write_available([], cfg.output_dir, f"{cfg.output_file}_st")

    rows = compute_source_stats(source_map, path_available)
    write_source_stats(rows, cfg.output_dir)

    cleanup_output_dir(cfg.output_dir, keep_only_whitelist_files=True)

    console.print("[green]Done[/green]")


if __name__ == "__main__":
    main()

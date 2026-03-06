"""
Unit tests for dedup, multi-credit stats, stats sorting, and CIDR parsing.
"""
from __future__ import annotations
import tempfile
import os
from pathlib import Path
from typing import Set, Dict


from whitelistchecker.normalize import normalize_key
from whitelistchecker.sources import extract_proxy_lines, merge_sources
from whitelistchecker.cidr import fetch_cidr_list
from whitelistchecker.stats import compute_source_stats, write_source_stats


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------

def test_normalize_strips_comment():
    assert normalize_key("vless://host#tag") == "vless://host"


def test_normalize_strips_whitespace():
    assert normalize_key("  vmess://host  ") == "vmess://host"


def test_normalize_strips_trailing_comment_and_spaces():
    assert normalize_key("trojan://host#name extra") == "trojan://host"


# ---------------------------------------------------------------------------
# local dedup (within a single source)
# ---------------------------------------------------------------------------

def test_extract_proxy_lines_dedup_not_done_by_extract():
    """extract_proxy_lines returns all matching lines including duplicates."""
    text = "vless://a\nvless://a\nvmess://b\n"
    lines = extract_proxy_lines(text)
    assert lines.count("vless://a") == 2  # no dedup at extract stage


# ---------------------------------------------------------------------------
# global dedup (across sources via merge_sources)
# ---------------------------------------------------------------------------

def test_merge_sources_global_dedup():
    """Same key from two different sources appears only once in global_pool."""
    from unittest.mock import patch

    calls = iter([
        "vless://a\nvless://b\n",  # source1
        "vless://b\nvless://c\n",  # source2 — 'b' is duplicate globally
    ])

    with patch("whitelistchecker.sources.fetch_text", side_effect=lambda url, **kw: next(calls)):
        pool, source_map = merge_sources(["http://s1", "http://s2"])

    keys = [normalize_key(u) for u in pool]
    assert keys.count("vless://b") == 1
    assert set(keys) == {"vless://a", "vless://b", "vless://c"}
    # source_map for s1 has 2 keys, s2 has 2 keys (including the duplicate)
    assert len(source_map["http://s1"]) == 2
    assert len(source_map["http://s2"]) == 2


# ---------------------------------------------------------------------------
# multi-credit stats
# ---------------------------------------------------------------------------

def test_compute_source_stats_multi_credit(tmp_path):
    """
    A working key that appears in multiple sources is counted for each source.
    """
    # available file: two working keys
    avail = tmp_path / "white-list_available"
    avail.write_text("vless://a\nvless://b\n", encoding="utf-8")

    source_map: Dict[str, Set[str]] = {
        "http://s1": {"vless://a", "vless://b"},   # 2 working
        "http://s2": {"vless://b", "vless://c"},   # 1 working (c not in avail)
        "http://s3": set(),                          # 0 working
    }

    rows = compute_source_stats(source_map, avail)

    as_dict = {url: cnt for url, cnt in rows}
    assert as_dict["http://s1"] == 2
    assert as_dict["http://s2"] == 1
    assert as_dict["http://s3"] == 0


def test_compute_source_stats_sorted(tmp_path):
    """Rows are sorted by working_count ASC, then URL ASC."""
    avail = tmp_path / "white-list_available"
    avail.write_text("vless://a\nvless://b\nvless://c\n", encoding="utf-8")

    source_map: Dict[str, Set[str]] = {
        "http://z": {"vless://a", "vless://b", "vless://c"},   # 3
        "http://a": {"vless://a"},                               # 1
        "http://m": {"vless://a", "vless://b"},                 # 2
    }

    rows = compute_source_stats(source_map, avail)
    counts = [cnt for _, cnt in rows]
    assert counts == sorted(counts), "rows should be sorted by count ASC"
    # for equal counts, URL should be sorted
    equal_groups: Dict[int, list] = {}
    for url, cnt in rows:
        equal_groups.setdefault(cnt, []).append(url)
    for urls in equal_groups.values():
        assert urls == sorted(urls)


def test_write_source_stats_format(tmp_path):
    rows = [("http://a", 0), ("http://b", 3)]
    write_source_stats(rows, str(tmp_path))
    content = (tmp_path / "white-list_available_source_stats.txt").read_text()
    assert content.startswith("# working_count\tsource_url\n")
    assert "0\thttp://a" in content
    assert "3\thttp://b" in content


# ---------------------------------------------------------------------------
# CIDR parsing — ignores junk
# ---------------------------------------------------------------------------

def test_cidr_parsing_ignores_junk(tmp_path):
    text = "# comment\n10.0.0.0/8\nnot-a-cidr\n192.168.1.0/24\n\n  \n172.16.0.0/12\n"
    from unittest.mock import patch
    with patch("whitelistchecker.cidr.fetch_text", return_value=text):
        cidrs = fetch_cidr_list("http://fake")
    assert cidrs == ["10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"]


# ---------------------------------------------------------------------------
# Source file parsing (comments, empty lines, multi-URL per line)
# ---------------------------------------------------------------------------

def test_load_source_urls_multi_url_per_line(tmp_path):
    from whitelistchecker.sources import load_source_urls
    f = tmp_path / "links.txt"
    f.write_text("# skip\nhttps://a.com https://b.com\n\nhttps://c.com\n", encoding="utf-8")
    urls = load_source_urls(str(f))
    assert urls == ["https://a.com", "https://b.com", "https://c.com"]

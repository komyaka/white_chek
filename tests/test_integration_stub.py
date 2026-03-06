"""
Integration test (offline, stub engine).

Uses ENGINE_MODE=stub and mocked HTTP sources to run the full pipeline
without any internet access or real proxy binaries. Verifies:
- Exactly 5 output files are produced
- Source stats file has correct format
- Notworkers exclusion works
- No internet calls are made
"""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest


PROXY_A = "vless://aaa@host-a:443?type=tcp#tag-a"
PROXY_B = "vmess://bbb@host-b:443#tag-b"
PROXY_C = "trojan://ccc@host-c:443#tag-c"

SOURCE_1 = f"{PROXY_A}\n{PROXY_B}\n"
SOURCE_2 = f"{PROXY_B}\n{PROXY_C}\n"  # B is a duplicate globally


REQUIRED_OUTPUT_FILES = {
    "white-list_available",
    "white-list_available(top100)",
    "white-list_available_st",
    "white-list_available_st(top100)",
    "white-list_available_source_stats.txt",
}


def _make_links_file(tmpdir: str, urls) -> str:
    path = os.path.join(tmpdir, "links.txt")
    with open(path, "w") as f:
        for u in urls:
            f.write(u + "\n")
    return path


def _fetch_text_mock(url, **kw):
    if "source1" in url:
        return SOURCE_1
    if "source2" in url:
        return SOURCE_2
    raise ValueError(f"Unexpected URL: {url}")


def test_stub_pipeline_produces_5_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        links_file = _make_links_file(tmpdir, ["http://source1", "http://source2"])
        output_dir = os.path.join(tmpdir, "output")

        env_overrides = {
            "ENGINE_MODE": "stub",
            "EGRESS_MODE": "off",
            "EGRESS_ALLOW_OFF": "true",
            "SPEED_TEST_ENABLED": "false",
            "RECHECK_PREVIOUS_WHITELISTS": "false",
            "USE_NOTWORKERS": "false",
            "KEEP_ONLY_WHITELIST_FILES": "true",
            "LINKS_FILE": links_file,
            "OUTPUT_DIR": output_dir,
        }

        with patch("whitelistchecker.sources.fetch_text", side_effect=_fetch_text_mock):
            with patch.dict(os.environ, env_overrides, clear=False):
                from whitelistchecker.main import main
                main([
                    "--links-file", links_file,
                    "--output-dir", output_dir,
                    "--engine-mode", "stub",
                    "--egress-mode", "off",
                    "--egress-allow-off",
                    "--no-speedtest",
                ])

        produced = {p.name for p in Path(output_dir).iterdir()}
        assert produced == REQUIRED_OUTPUT_FILES, f"Expected {REQUIRED_OUTPUT_FILES}, got {produced}"


def test_stub_pipeline_source_stats():
    with tempfile.TemporaryDirectory() as tmpdir:
        links_file = _make_links_file(tmpdir, ["http://source1", "http://source2"])
        output_dir = os.path.join(tmpdir, "output")

        with patch("whitelistchecker.sources.fetch_text", side_effect=_fetch_text_mock):
            from whitelistchecker.main import main
            main([
                "--links-file", links_file,
                "--output-dir", output_dir,
                "--engine-mode", "stub",
                "--egress-mode", "off",
                    "--egress-allow-off",
                "--no-speedtest",
            ])

        stats = (Path(output_dir) / "white-list_available_source_stats.txt").read_text()
        assert stats.startswith("# working_count\tsource_url")
        assert "http://source1" in stats
        assert "http://source2" in stats


def test_stub_pipeline_notworkers_exclusion():
    """Keys in notworkers file are excluded from checks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        links_file = _make_links_file(tmpdir, ["http://source1"])
        output_dir = os.path.join(tmpdir, "output")
        os.makedirs(output_dir, exist_ok=True)

        # Put PROXY_A key in notworkers
        from whitelistchecker.normalize import normalize_key
        nw_key = normalize_key(PROXY_A)
        (Path(output_dir) / "notworkers").write_text(nw_key + "\n")

        with patch("whitelistchecker.sources.fetch_text", side_effect=_fetch_text_mock):
            from whitelistchecker.main import main
            main([
                "--links-file", links_file,
                "--output-dir", output_dir,
                "--engine-mode", "stub",
                "--egress-mode", "off",
                    "--egress-allow-off",
                "--no-speedtest",
                "--use-notworkers",
                "--no-recheck-previous",
            ])

        available = (Path(output_dir) / "white-list_available").read_text()
        # PROXY_A should NOT appear in the output since it was in notworkers
        assert normalize_key(PROXY_A) not in available


def test_stub_pipeline_notworkers_append():
    """Failing keys are appended to notworkers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        links_file = _make_links_file(tmpdir, ["http://source1"])
        output_dir = os.path.join(tmpdir, "output")
        os.makedirs(output_dir, exist_ok=True)

        # Patch stub so PROXY_B fails
        from whitelistchecker.engines.xray import XrayResult
        from whitelistchecker.normalize import normalize_key

        def stub_with_failure(pool, cfg, base_port):
            results = []
            for i, uri in enumerate(pool):
                key = normalize_key(uri)
                # Fail PROXY_B
                ok = normalize_key(uri) != normalize_key(PROXY_B)
                results.append(XrayResult(key=key, uri=uri, latency_ms=float(100 + i), ok=ok,
                                          reason=None if ok else "stub-fail"))
            return results

        with patch("whitelistchecker.sources.fetch_text", side_effect=_fetch_text_mock):
            with patch("whitelistchecker.main._run_checks_stub", side_effect=stub_with_failure):
                with patch.dict(os.environ, {"KEEP_ONLY_WHITELIST_FILES": "false"}):
                    from whitelistchecker.main import main
                    main([
                        "--links-file", links_file,
                        "--output-dir", output_dir,
                        "--engine-mode", "stub",
                        "--egress-mode", "off",
                    "--egress-allow-off",
                        "--no-speedtest",
                        "--use-notworkers",
                        "--no-recheck-previous",
                    ])

        nw = (Path(output_dir) / "notworkers").read_text()
        # notworkers stores the original URI line; PROXY_B should appear
        assert PROXY_B in nw


def test_stub_pipeline_speedtest_produces_st_files():
    """When speedtest disabled, _st files are copies of available."""
    with tempfile.TemporaryDirectory() as tmpdir:
        links_file = _make_links_file(tmpdir, ["http://source1"])
        output_dir = os.path.join(tmpdir, "output")

        with patch("whitelistchecker.sources.fetch_text", side_effect=_fetch_text_mock):
            from whitelistchecker.main import main
            main([
                "--links-file", links_file,
                "--output-dir", output_dir,
                "--engine-mode", "stub",
                "--egress-mode", "off",
                    "--egress-allow-off",
                "--no-speedtest",
                "--no-recheck-previous",
            ])

        avail = (Path(output_dir) / "white-list_available").read_text()
        st = (Path(output_dir) / "white-list_available_st").read_text()
        assert avail == st

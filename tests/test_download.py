"""
Unit tests for the binary auto-download module (download.py).

All network calls are mocked – no actual downloads occur.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import stat
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from whitelistchecker.download import (
    BinaryDownloadError,
    _arch,
    _download_hysteria,
    _download_xray,
    _latest_github_tag,
    _os_name,
    _parse_sha256sum_line,
    _sha256_of_bytes,
    cache_dir,
    ensure_binary,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_zip(filename: str, content: bytes) -> bytes:
    """Create an in-memory zip containing one file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# _os_name
# ---------------------------------------------------------------------------

def test_os_name_linux():
    with patch("whitelistchecker.download.platform.system", return_value="Linux"):
        assert _os_name() == "linux"


def test_os_name_windows():
    with patch("whitelistchecker.download.platform.system", return_value="Windows"):
        assert _os_name() == "windows"


def test_os_name_unsupported():
    with patch("whitelistchecker.download.platform.system", return_value="Darwin"):
        with pytest.raises(BinaryDownloadError, match="Unsupported OS"):
            _os_name()


# ---------------------------------------------------------------------------
# _arch
# ---------------------------------------------------------------------------

def test_arch_x86_64():
    with patch("whitelistchecker.download.platform.machine", return_value="x86_64"):
        assert _arch() == "x86_64"


def test_arch_amd64_alias():
    with patch("whitelistchecker.download.platform.machine", return_value="AMD64"):
        assert _arch() == "x86_64"


def test_arch_arm64():
    with patch("whitelistchecker.download.platform.machine", return_value="aarch64"):
        assert _arch() == "arm64"


def test_arch_unsupported():
    with patch("whitelistchecker.download.platform.machine", return_value="mips"):
        with pytest.raises(BinaryDownloadError, match="Unsupported architecture"):
            _arch()


# ---------------------------------------------------------------------------
# _parse_sha256sum_line
# ---------------------------------------------------------------------------

def test_parse_sha256sum_exact_match():
    text = "abc123  hysteria-linux-amd64\n"
    assert _parse_sha256sum_line(text, "hysteria-linux-amd64") == "abc123"


def test_parse_sha256sum_binary_mode_marker():
    text = "abc123 *hysteria-linux-amd64\n"
    assert _parse_sha256sum_line(text, "hysteria-linux-amd64") == "abc123"


def test_parse_sha256sum_no_match():
    text = "abc123  other-file\n"
    assert _parse_sha256sum_line(text, "hysteria-linux-amd64") is None


# ---------------------------------------------------------------------------
# _latest_github_tag
# ---------------------------------------------------------------------------

def test_latest_github_tag():
    payload = json.dumps({"tag_name": "v1.2.3"}).encode()
    with patch("whitelistchecker.download._http_get", return_value=payload):
        assert _latest_github_tag("XTLS/Xray-core") == "v1.2.3"


def test_latest_github_tag_bad_json():
    with patch("whitelistchecker.download._http_get", return_value=b"not-json"):
        with pytest.raises(BinaryDownloadError, match="Could not parse"):
            _latest_github_tag("XTLS/Xray-core")


# ---------------------------------------------------------------------------
# _download_xray
# ---------------------------------------------------------------------------

def test_download_xray_linux_x86(tmp_path):
    xray_binary = b"\x7fELF fake xray binary"
    zip_data = _make_zip("xray", xray_binary)
    dgst_text = f"SHA-256 = {_sha256(zip_data)}\nMD5 = abcd\n".encode()

    responses = {
        "api.github.com": json.dumps({"tag_name": "v1.0.0"}).encode(),
        ".dgst": dgst_text,
        "Xray-linux-64.zip": zip_data,
    }

    def _fake_http_get(url, **kw):
        for key, val in responses.items():
            if key in url:
                return val
        raise AssertionError(f"Unexpected URL: {url}")

    with patch("whitelistchecker.download.platform.system", return_value="Linux"):
        with patch("whitelistchecker.download.platform.machine", return_value="x86_64"):
            with patch("whitelistchecker.download._http_get", side_effect=_fake_http_get):
                dest = _download_xray(tmp_path)

    assert dest.exists()
    assert dest.read_bytes() == xray_binary
    # Should be executable on Linux
    if platform.system() != "Windows":
        assert dest.stat().st_mode & stat.S_IXUSR


def test_download_xray_sha256_mismatch(tmp_path):
    zip_data = b"fake zip"
    dgst_text = b"SHA-256 = 0000000000000000000000000000000000000000000000000000000000000000\n"

    responses = {
        "api.github.com": json.dumps({"tag_name": "v1.0.0"}).encode(),
        ".dgst": dgst_text,
        "Xray-linux-64.zip": zip_data,
    }

    def _fake_http_get(url, **kw):
        for key, val in responses.items():
            if key in url:
                return val
        raise AssertionError(f"Unexpected URL: {url}")

    with patch("whitelistchecker.download.platform.system", return_value="Linux"):
        with patch("whitelistchecker.download.platform.machine", return_value="x86_64"):
            with patch("whitelistchecker.download._http_get", side_effect=_fake_http_get):
                with pytest.raises(BinaryDownloadError, match="SHA-256 mismatch"):
                    _download_xray(tmp_path)


def test_download_xray_unsupported_platform(tmp_path):
    with patch("whitelistchecker.download.platform.system", return_value="Linux"):
        with patch("whitelistchecker.download.platform.machine", return_value="mips"):
            with pytest.raises(BinaryDownloadError, match="Unsupported architecture"):
                _download_xray(tmp_path)


# ---------------------------------------------------------------------------
# _download_hysteria
# ---------------------------------------------------------------------------

def test_download_hysteria_linux_x86(tmp_path):
    hy_binary = b"fake hysteria binary"
    sha_text = f"{_sha256(hy_binary)}  hysteria-linux-amd64\n".encode()

    responses = {
        "api.github.com": json.dumps({"tag_name": "v2.0.0"}).encode(),
        ".sha256sum": sha_text,
        "hysteria-linux-amd64": hy_binary,
    }

    def _fake_http_get(url, **kw):
        for key, val in responses.items():
            if key in url:
                return val
        raise AssertionError(f"Unexpected URL: {url}")

    with patch("whitelistchecker.download.platform.system", return_value="Linux"):
        with patch("whitelistchecker.download.platform.machine", return_value="x86_64"):
            with patch("whitelistchecker.download._http_get", side_effect=_fake_http_get):
                dest = _download_hysteria(tmp_path)

    assert dest.exists()
    assert dest.read_bytes() == hy_binary
    if platform.system() != "Windows":
        assert dest.stat().st_mode & stat.S_IXUSR


def test_download_hysteria_sha256_mismatch(tmp_path):
    hy_binary = b"fake hysteria binary"
    sha_text = b"0000000000000000000000000000000000000000000000000000000000000000  hysteria-linux-amd64\n"

    responses = {
        "api.github.com": json.dumps({"tag_name": "v2.0.0"}).encode(),
        ".sha256sum": sha_text,
        "hysteria-linux-amd64": hy_binary,
    }

    def _fake_http_get(url, **kw):
        for key, val in responses.items():
            if key in url:
                return val
        raise AssertionError(f"Unexpected URL: {url}")

    with patch("whitelistchecker.download.platform.system", return_value="Linux"):
        with patch("whitelistchecker.download.platform.machine", return_value="x86_64"):
            with patch("whitelistchecker.download._http_get", side_effect=_fake_http_get):
                with pytest.raises(BinaryDownloadError, match="SHA-256 mismatch"):
                    _download_hysteria(tmp_path)


# ---------------------------------------------------------------------------
# ensure_binary – resolution order and caching
# ---------------------------------------------------------------------------

def test_ensure_binary_uses_explicit_path(tmp_path):
    fake_bin = tmp_path / "xray"
    fake_bin.write_bytes(b"fake")
    result = ensure_binary("xray", explicit_path=str(fake_bin))
    assert result == str(fake_bin)


def test_ensure_binary_explicit_path_missing_raises(tmp_path):
    with pytest.raises(BinaryDownloadError, match="not found at explicit path"):
        ensure_binary("xray", explicit_path=str(tmp_path / "missing"))


def test_ensure_binary_uses_env_var(tmp_path, monkeypatch):
    fake_bin = tmp_path / "xray"
    fake_bin.write_bytes(b"fake")
    monkeypatch.setenv("XRAY_PATH", str(fake_bin))
    result = ensure_binary("xray", env_var="XRAY_PATH")
    assert result == str(fake_bin)


def test_ensure_binary_uses_path_lookup(tmp_path):
    with patch("whitelistchecker.download.shutil.which", return_value="/usr/bin/xray"):
        result = ensure_binary("xray")
    assert result == "/usr/bin/xray"


def test_ensure_binary_uses_cache(tmp_path):
    fake_bin = tmp_path / "xray"
    fake_bin.write_bytes(b"cached xray")

    with patch("whitelistchecker.download.shutil.which", return_value=None):
        with patch("whitelistchecker.download.cache_dir", return_value=tmp_path):
            result = ensure_binary("xray")
    assert result == str(fake_bin)


def test_ensure_binary_cache_reuse_no_download(tmp_path):
    """If binary is already in cache, no download should happen."""
    fake_bin = tmp_path / "xray"
    fake_bin.write_bytes(b"cached xray")

    download_called = []

    def _fake_download(dest_dir):
        download_called.append(True)
        return dest_dir / "xray"

    with patch("whitelistchecker.download.shutil.which", return_value=None):
        with patch("whitelistchecker.download.cache_dir", return_value=tmp_path):
            with patch("whitelistchecker.download._download_xray", _fake_download):
                ensure_binary("xray")

    assert download_called == [], "Download should not have been called when cache exists"


def test_ensure_binary_downloads_when_not_found(tmp_path):
    """When binary is not in PATH or cache, it should be auto-downloaded."""
    downloaded_to = []

    def _fake_download(dest_dir):
        dest = dest_dir / "xray"
        dest.write_bytes(b"downloaded xray")
        downloaded_to.append(str(dest))
        return dest

    with patch("whitelistchecker.download.shutil.which", return_value=None):
        with patch("whitelistchecker.download.cache_dir", return_value=tmp_path):
            with patch("whitelistchecker.download._download_xray", _fake_download):
                result = ensure_binary("xray")

    assert downloaded_to, "Download should have been called"
    assert result == downloaded_to[0]


def test_ensure_binary_no_download_raises_when_not_allowed(tmp_path):
    with patch("whitelistchecker.download.shutil.which", return_value=None):
        with patch("whitelistchecker.download.cache_dir", return_value=tmp_path):
            with pytest.raises(BinaryDownloadError, match="not found in PATH or cache"):
                ensure_binary("xray", allow_download=False)


def test_ensure_binary_unknown_name_raises(tmp_path):
    with patch("whitelistchecker.download.shutil.which", return_value=None):
        with patch("whitelistchecker.download.cache_dir", return_value=tmp_path):
            with pytest.raises(BinaryDownloadError, match="Auto-download is not supported"):
                ensure_binary("unknown_tool")

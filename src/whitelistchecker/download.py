"""
Binary auto-download for Xray and Hysteria.

Downloads official releases for the current OS/arch, caches them in
~/.cache/white_chek/bin, verifies SHA256, and marks as executable.
Supported platforms: Linux x86_64/arm64, Windows x64.
"""
from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import stat
import sys
import zipfile
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError


class BinaryDownloadError(RuntimeError):
    """Raised when a binary cannot be downloaded or verified."""


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def _os_name() -> str:
    s = platform.system().lower()
    if s == "linux":
        return "linux"
    if s == "windows":
        return "windows"
    raise BinaryDownloadError(
        f"Unsupported OS '{platform.system()}'. "
        "Auto-download is supported on Linux and Windows only. "
        "Please install xray/hysteria manually and set XRAY_PATH / HYSTERIA_PATH."
    )


def _arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    raise BinaryDownloadError(
        f"Unsupported architecture '{platform.machine()}'. "
        "Auto-download is supported on x86_64 and arm64 only. "
        "Please install xray/hysteria manually and set XRAY_PATH / HYSTERIA_PATH."
    )


# ---------------------------------------------------------------------------
# Cache directory
# ---------------------------------------------------------------------------

def cache_dir() -> Path:
    """Return (and create) the binary cache directory."""
    d = Path.home() / ".cache" / "white_chek" / "bin"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# HTTP helper (uses only stdlib urllib)
# ---------------------------------------------------------------------------

_HEADERS = {"User-Agent": "white_chek/binary-downloader"}


def _http_get(url: str, timeout: int = 60) -> bytes:
    req = Request(url, headers=_HEADERS)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except URLError as exc:
        raise BinaryDownloadError(f"Network error downloading {url}: {exc}") from exc


def _latest_github_tag(repo: str) -> str:
    """Return the latest release tag for a GitHub repo (e.g. 'v1.2.3')."""
    import json
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    data = _http_get(url, timeout=15)
    try:
        info = json.loads(data)
        tag = info["tag_name"]
    except (KeyError, ValueError) as exc:
        raise BinaryDownloadError(
            f"Could not parse latest release for {repo}: {exc}"
        ) from exc
    return tag


# ---------------------------------------------------------------------------
# SHA-256 verification
# ---------------------------------------------------------------------------

def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_sha256sum_line(text: str, filename: str) -> Optional[str]:
    """Parse a sha256sum-style file for *filename* and return the hex digest."""
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            digest, name = parts
            # strip leading '*' (binary mode marker)
            name = name.lstrip("*").strip()
            if os.path.basename(name) == filename:
                return digest.strip().lower()
    return None


# ---------------------------------------------------------------------------
# Xray download
# ---------------------------------------------------------------------------

# Map (os_name, arch) -> (zip_filename, binary_inside_zip)
_XRAY_ASSETS: dict[tuple[str, str], tuple[str, str]] = {
    ("linux",   "x86_64"): ("Xray-linux-64.zip",          "xray"),
    ("linux",   "arm64"):  ("Xray-linux-arm64-v8a.zip",    "xray"),
    ("windows", "x86_64"): ("Xray-windows-64.zip",         "xray.exe"),
}


def _download_xray(dest_dir: Path) -> Path:
    """Download the latest Xray binary into *dest_dir* and return its path."""
    os_name = _os_name()
    arch = _arch()
    key = (os_name, arch)
    if key not in _XRAY_ASSETS:
        raise BinaryDownloadError(
            f"No Xray release asset for {os_name}/{arch}. "
            "Please install xray manually and set XRAY_PATH."
        )

    tag = _latest_github_tag("XTLS/Xray-core")
    zip_name, bin_name = _XRAY_ASSETS[key]
    base_url = f"https://github.com/XTLS/Xray-core/releases/download/{tag}"

    # Download SHA256 digest file
    dgst_url = f"{base_url}/{zip_name}.dgst"
    try:
        dgst_text = _http_get(dgst_url).decode("utf-8", errors="replace")
    except BinaryDownloadError:
        dgst_text = ""

    # Download zip
    zip_url = f"{base_url}/{zip_name}"
    zip_data = _http_get(zip_url)

    # Verify SHA256 if digest is available
    if dgst_text:
        got = _sha256_of_bytes(zip_data)
        # Xray .dgst format: "SHA-256 = <hex>"
        expected = None
        for line in dgst_text.splitlines():
            if "SHA-256" in line or "sha256" in line.lower():
                parts = line.split("=", 1)
                if len(parts) == 2:
                    expected = parts[1].strip().lower()
                    break
        if expected and got != expected:
            raise BinaryDownloadError(
                f"SHA-256 mismatch for {zip_name}: expected {expected}, got {got}"
            )

    # Extract binary from zip
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        names = zf.namelist()
        # binary may be at root or inside a subdir
        candidates = [n for n in names if os.path.basename(n) == bin_name]
        if not candidates:
            raise BinaryDownloadError(
                f"Binary '{bin_name}' not found in {zip_name}. "
                f"Archive contents: {names[:10]}"
            )
        extracted = zf.read(candidates[0])

    dest = dest_dir / bin_name
    dest.write_bytes(extracted)
    if os_name != "windows":
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return dest


# ---------------------------------------------------------------------------
# Hysteria download
# ---------------------------------------------------------------------------

# Map (os_name, arch) -> (asset_filename, local_name)
_HYSTERIA_ASSETS: dict[tuple[str, str], tuple[str, str]] = {
    ("linux",   "x86_64"): ("hysteria-linux-amd64",     "hysteria"),
    ("linux",   "arm64"):  ("hysteria-linux-arm64",      "hysteria"),
    ("windows", "x86_64"): ("hysteria-windows-amd64.exe", "hysteria.exe"),
}


def _download_hysteria(dest_dir: Path) -> Path:
    """Download the latest Hysteria binary into *dest_dir* and return its path."""
    os_name = _os_name()
    arch = _arch()
    key = (os_name, arch)
    if key not in _HYSTERIA_ASSETS:
        raise BinaryDownloadError(
            f"No Hysteria release asset for {os_name}/{arch}. "
            "Please install hysteria manually and set HYSTERIA_PATH."
        )

    tag = _latest_github_tag("apernet/hysteria")
    asset_name, local_name = _HYSTERIA_ASSETS[key]
    base_url = f"https://github.com/apernet/hysteria/releases/download/{tag}"

    # Download SHA256 checksum file
    sha_url = f"{base_url}/{asset_name}.sha256sum"
    try:
        sha_text = _http_get(sha_url).decode("utf-8", errors="replace")
    except BinaryDownloadError:
        sha_text = ""

    # Download binary
    bin_url = f"{base_url}/{asset_name}"
    bin_data = _http_get(bin_url)

    # Verify SHA256
    if sha_text:
        got = _sha256_of_bytes(bin_data)
        expected = _parse_sha256sum_line(sha_text, asset_name)
        if expected and got != expected:
            raise BinaryDownloadError(
                f"SHA-256 mismatch for {asset_name}: expected {expected}, got {got}"
            )

    dest = dest_dir / local_name
    dest.write_bytes(bin_data)
    if os_name != "windows":
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return dest


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ensure_binary(
    name: str,
    explicit_path: Optional[str] = None,
    env_var: Optional[str] = None,
    allow_download: bool = True,
) -> str:
    """Return a path to the *name* binary (xray or hysteria).

    Resolution order:
    1. *explicit_path* argument
    2. *env_var* environment variable (e.g. XRAY_PATH)
    3. PATH lookup (shutil.which)
    4. Cache directory  ~/.cache/white_chek/bin
    5. Auto-download from official GitHub release (if *allow_download* is True)

    Raises ``BinaryDownloadError`` (a subclass of ``FileNotFoundError``) if the
    binary cannot be found or downloaded.
    """
    candidate = explicit_path or (os.environ.get(env_var) if env_var else None) or name

    # Absolute path given explicitly
    if os.path.isabs(candidate):
        if os.path.exists(candidate):
            return candidate
        raise BinaryDownloadError(f"Binary not found at explicit path: {candidate}")

    # PATH lookup
    resolved = shutil.which(candidate)
    if resolved is not None:
        return resolved

    # Cache directory lookup
    bin_name_win = f"{name}.exe"
    cd = cache_dir()
    for fname in (name, bin_name_win):
        cached = cd / fname
        if cached.exists():
            return str(cached)

    if not allow_download:
        raise BinaryDownloadError(
            f"Binary '{name}' not found in PATH or cache. "
            "Set XRAY_PATH / HYSTERIA_PATH or install manually."
        )

    # Auto-download
    if name == "xray":
        dest = _download_xray(cd)
    elif name in ("hysteria",):
        dest = _download_hysteria(cd)
    else:
        raise BinaryDownloadError(
            f"Auto-download is not supported for binary '{name}'. "
            "Please install it manually."
        )

    return str(dest)

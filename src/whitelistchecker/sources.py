from __future__ import annotations
import httpx
from typing import List, Dict, Set, Tuple
from .normalize import normalize_key

SUPPORTED_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hysteria2://", "hy2://")

class SourceFetchError(Exception):
    def __init__(self, url: str, reason: str):
        super().__init__(f"{url}: {reason}")
        self.url = url
        self.reason = reason


def load_source_urls(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            for part in parts:
                if part.startswith("http://") or part.startswith("https://"):
                    urls.append(part)
    return urls


def fetch_text(url: str, timeout: int = 30) -> str:
    try:
        resp = httpx.get(url, timeout=timeout, headers={"User-Agent": "whitelistchecker/0.1"})
    except Exception as e:
        raise SourceFetchError(url, f"network error: {e}")
    if resp.status_code >= 400:
        raise SourceFetchError(url, f"http {resp.status_code}")
    return resp.text


def extract_proxy_lines(text: str) -> List[str]:
    lines: List[str] = []
    for raw in text.splitlines():
        s = raw.strip()
        if any(s.startswith(p) for p in SUPPORTED_SCHEMES):
            lines.append(s)
    return lines


def merge_sources(urls: List[str]) -> Tuple[List[str], Dict[str, Set[str]]]:
    global_pool: List[str] = []
    seen_global: Set[str] = set()
    source_map: Dict[str, Set[str]] = {}

    for idx, url in enumerate(urls, start=1):
        try:
            txt = fetch_text(url)
        except SourceFetchError:
            source_map[url] = set()
            continue
        proxy_lines = extract_proxy_lines(txt)
        local_set: Set[str] = set()
        for line in proxy_lines:
            key = normalize_key(line)
            if key in local_set:
                continue
            local_set.add(key)
            if key not in seen_global:
                global_pool.append(line)
                seen_global.add(key)
        source_map[url] = local_set
    return global_pool, source_map

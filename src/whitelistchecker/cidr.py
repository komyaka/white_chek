from __future__ import annotations
import ipaddress
from typing import List
from .sources import fetch_text, SourceFetchError


def fetch_cidr_list(url: str, timeout: int = 30) -> List[str]:
    try:
        text = fetch_text(url, timeout=timeout)
    except SourceFetchError as e:
        raise
    cidrs: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            ipaddress.ip_network(s, strict=False)
            cidrs.append(s)
        except ValueError:
            continue
    return cidrs

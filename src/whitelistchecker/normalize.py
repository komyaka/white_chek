from __future__ import annotations

def normalize_key(line: str) -> str:
    first_token = line.split()[0] if line else ""
    if "#" in first_token:
        first_token = first_token.split("#", 1)[0]
    return first_token.strip()

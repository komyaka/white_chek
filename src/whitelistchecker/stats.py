from __future__ import annotations
from pathlib import Path
from typing import Dict, Set, List, Tuple
from .normalize import normalize_key


def compute_source_stats(source_map: Dict[str, Set[str]], available_path: Path) -> List[Tuple[str, int]]:
    if not available_path.exists():
        return []
    working = {normalize_key(line.strip()) for line in available_path.read_text(encoding="utf-8").splitlines() if line.strip()}
    rows = []
    for url, keys in source_map.items():
        count = len(keys & working)
        rows.append((url, count))
    rows.sort(key=lambda x: (x[1], x[0]))
    return rows


def write_source_stats(rows: List[Tuple[str, int]], output_dir: str):
    path = Path(output_dir) / "white-list_available_source_stats.txt"
    lines = ["# working_count\tsource_url"]
    for url, count in rows:
        lines.append(f"{count}\t{url}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path

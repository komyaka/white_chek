from __future__ import annotations
from pathlib import Path
from typing import List


def write_lines(path: Path, lines: List[str]):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_available(ok_results, output_dir: str, base_name: str):
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sorted_results = sorted(
        [r for r in ok_results if getattr(r, "ok", False)],
        key=lambda r: getattr(r, "latency_ms", 1e9),
    )
    lines = [r.uri for r in sorted_results]
    path_available = out_dir / base_name
    write_lines(path_available, lines)
    path_top = out_dir / f"{base_name}(top100)"
    write_lines(path_top, lines[:100])
    return path_available, path_top

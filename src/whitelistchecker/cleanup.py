from __future__ import annotations
from pathlib import Path
from typing import List

REQUIRED_FILES = {
    "white-list_available",
    "white-list_available(top100)",
    "white-list_available_st",
    "white-list_available_st(top100)",
    "white-list_available_source_stats.txt",
}


def cleanup_output_dir(output_dir: str, keep_only_whitelist_files: bool = True):
    p = Path(output_dir)
    if not p.exists():
        return
    if not keep_only_whitelist_files:
        return
    for child in p.iterdir():
        if child.name in REQUIRED_FILES:
            continue
        if child.is_file():
            child.unlink()
        else:
            shutil.rmtree(child, ignore_errors=True)

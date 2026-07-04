"""File system utilities."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def count_lines(filepath: Path) -> int:
    """Count total lines in a file without loading it entirely."""
    count = 0
    with open(filepath, "rb") as fh:
        for _ in fh:
            count += 1
    return count


def file_size_human(filepath: Path) -> str:
    """Return human-readable file size."""
    size = float(filepath.stat().st_size)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def readable(filepath: Path) -> bool:
    """Check whether the current user can read the file."""
    return os.access(filepath, os.R_OK)


def ensure_parent(filepath: Path) -> None:
    """Create parent directories for a file path."""
    filepath.parent.mkdir(parents=True, exist_ok=True)


def available_disk_space(path: Path) -> int:
    """Return available disk space in bytes for the filesystem containing path."""
    usage = shutil.disk_usage(path)
    return usage.free

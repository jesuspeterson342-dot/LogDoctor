"""Time and date parsing utilities."""

from __future__ import annotations

import re
from datetime import datetime

NGINX_TIME_RE = re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
SYSLOG_TIME_RE = re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
ISO_TIME_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
)
PACMAN_TIME_RE = re.compile(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\]")
DOCKER_TIME_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
)
PYTHON_TRACEBACK_TIME_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)",
)


def parse_nginx_time(s: str) -> datetime | None:
    """Parse nginx-style timestamp like '2024/01/15 03:22:11'."""
    m = NGINX_TIME_RE.search(s)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
    return None


def parse_iso_time(s: str) -> datetime | None:
    """Parse ISO 8601 timestamps."""
    m = ISO_TIME_RE.search(s)
    if m:
        raw = m.group(1)
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None


def parse_pacman_time(s: str) -> datetime | None:
    """Parse pacman log timestamp like '[2024-01-15T03:22:11+0000]'."""
    m = PACMAN_TIME_RE.search(s)
    if m:
        raw = m.group(1)
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None


def parse_docker_time(s: str) -> datetime | None:
    """Parse Docker timestamp."""
    return parse_iso_time(s)


def parse_python_time(s: str) -> datetime | None:
    """Parse Python traceback timestamp like '2024-01-15 03:22:11,123'."""
    m = PYTHON_TRACEBACK_TIME_RE.search(s)
    if m:
        raw = m.group(1)
        for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None


def parse_auto(s: str) -> datetime | None:
    """Try all timestamp parsers and return the first match."""
    for parser in (
        parse_pacman_time,
        parse_iso_time,
        parse_nginx_time,
        parse_docker_time,
        parse_python_time,
    ):
        result = parser(s)
        if result:
            return result
    return None


def format_duration_ms(ms: float) -> str:
    """Format milliseconds as a human-readable string."""
    if ms < 1000:
        return f"{ms:.0f}ms"
    s = ms / 1000
    if s < 60:
        return f"{s:.2f}s"
    return f"{s / 60:.1f}min"

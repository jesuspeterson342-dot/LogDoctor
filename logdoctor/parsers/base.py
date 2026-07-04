"""Base parser class and log type detection."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from logdoctor.models import LogEvent, LogType


class BaseParser(ABC):
    """Abstract base for all log parsers."""

    log_type: LogType = LogType.GENERIC
    SNIFF_LINES: int = 50

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> LogEvent | None:
        """Parse a single line into a LogEvent, or skip if not relevant."""

    def parse_file(self, filepath: str) -> Iterator[LogEvent]:
        """Parse all lines in a file, yielding LogEvents."""
        path = Path(filepath)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, start=1):
                line = line.rstrip("\n\r")
                event = self.parse_line(line, i)
                if event is not None:
                    yield event

    def parse_lines(self, lines: list[str]) -> list[LogEvent]:
        """Parse a list of lines, returning matched events."""
        events: list[LogEvent] = []
        for i, line in enumerate(lines, start=1):
            line = line.rstrip("\n\r")
            event = self.parse_line(line, i)
            if event is not None:
                events.append(event)
        return events


# --- Log type detection based on file content sniffing ---

NGINX_ERROR_RE = re.compile(
    r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[(?:error|crit|alert|emerg)\]",
)
NGINX_ACCESS_RE = re.compile(
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+\[",
)
DOCKER_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+\S+",
)
PYTHON_TB_RE = re.compile(
    r"(?:Traceback \(most recent call last\)|\bFile\s+.+,\s+line\s+\d+)",
)
PACMAN_RE = re.compile(
    r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4})?\]"
    r"\s+\[(?:ALPM|PACMAN)\]",
)
SYSTEMD_RE = re.compile(
    r"^\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\w+\s+(?:systemd|kernel)",
)


def detect_log_type(filepath: str) -> LogType:
    """Detect log type by reading the first N lines of a file."""
    path = Path(filepath)
    if not path.exists():
        return LogType.GENERIC

    counts: dict[LogType, int] = {t: 0 for t in LogType}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= BaseParser.SNIFF_LINES:
                    break
                line = line.strip()
                if not line:
                    continue
                if NGINX_ERROR_RE.search(line):
                    counts[LogType.NGINX_ERROR] += 1
                elif NGINX_ACCESS_RE.search(line):
                    counts[LogType.NGINX_ACCESS] += 1
                elif DOCKER_RE.match(line):
                    counts[LogType.DOCKER] += 1
                elif PYTHON_TB_RE.search(line):
                    counts[LogType.PYTHON_TRACEBACK] += 1
                elif PACMAN_RE.match(line):
                    counts[LogType.PACMAN] += 1
                elif SYSTEMD_RE.match(line):
                    counts[LogType.SYSTEMD] += 1
                else:
                    counts[LogType.GENERIC] += 1
    except OSError:
        return LogType.GENERIC

    # Prefer specific types over generic when they have at least 2 matches
    specific = {t: c for t, c in counts.items() if t != LogType.GENERIC and c >= 2}
    if specific:
        return max(specific, key=lambda k: specific[k])

    best_type = max(counts, key=lambda k: counts[k])
    if counts[best_type] == 0:
        return LogType.GENERIC
    return best_type

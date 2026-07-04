"""Parser for Arch Linux pacman.log."""

from __future__ import annotations

import re

from logdoctor.models import LogEvent, LogType, Severity
from logdoctor.parsers.base import BaseParser
from logdoctor.utils.time_utils import parse_pacman_time

# Pacman log format:
# [2024-01-15T03:22:11+0000] [ALPM] action package-version
PACMAN_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+"
    r"\[(?P<subsystem>ALPM|PACMAN)\]\s+"
    r"(?P<message>.+)"
)

# Error indicators
ERROR_RE = re.compile(
    r"(?:error|failed|warning|corrupt|conflict|invalid|not found|unresolvable)",
    re.IGNORECASE,
)

FAILED_TRANSACTION_RE = re.compile(r"failed to commit transaction", re.IGNORECASE)
KEYRING_RE = re.compile(r"keyring|key.*invalid|signature.*invalid|unknown trust", re.IGNORECASE)
DISK_FULL_RE = re.compile(r"no space left|disk full|insufficient.*space", re.IGNORECASE)


class PacmanParser(BaseParser):
    """Parse pacman.log from Arch Linux."""

    log_type = LogType.PACMAN

    def parse_line(self, line: str, line_number: int) -> LogEvent | None:
        m = PACMAN_RE.match(line)
        if not m:
            return None

        ts = parse_pacman_time(m.group("timestamp"))
        message = m.group("message")
        subsystem = m.group("subsystem")

        severity = Severity.LOW
        if FAILED_TRANSACTION_RE.search(message):
            severity = Severity.CRITICAL
        elif KEYRING_RE.search(message):
            severity = Severity.HIGH
        elif DISK_FULL_RE.search(message):
            severity = Severity.CRITICAL
        elif ERROR_RE.search(message):
            severity = Severity.MEDIUM

        return LogEvent(
            timestamp=ts,
            level="info",
            source=f"pacman/{subsystem.lower()}",
            message=message,
            category="pacman",
            severity=severity,
            line_number=line_number,
            raw_line=line,
        )

"""Parser for Docker Compose logs."""

from __future__ import annotations

import re

from logdoctor.models import LogEvent, LogType, Severity
from logdoctor.parsers.base import BaseParser
from logdoctor.utils.time_utils import parse_docker_time

# Docker log format:
# 2024-01-15T03:22:11.123456789Z container_name  message
DOCKER_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<message>.+)"
)

EXIT_RE = re.compile(r"(?:exited with code|Container.*(?: exited |stopped|killed))", re.IGNORECASE)
OOM_RE = re.compile(r"out of memory|oom|cannot allocate", re.IGNORECASE)
PULL_FAIL_RE = re.compile(r"(?:pull|image).*fail|failed to pull|manifest.*unknown", re.IGNORECASE)
PORT_CONFLICT_RE = re.compile(r"port.*already.*allocat|address already in use", re.IGNORECASE)
CRASH_RE = re.compile(r"panic|fatal|segmentation fault|segfault", re.IGNORECASE)


class DockerParser(BaseParser):
    """Parse Docker Compose log output."""

    log_type = LogType.DOCKER

    def parse_line(self, line: str, line_number: int) -> LogEvent | None:
        m = DOCKER_LINE_RE.match(line)
        if not m:
            return None

        ts = parse_docker_time(m.group("timestamp"))
        source = m.group("source")
        message = m.group("message")

        severity = Severity.LOW
        if EXIT_RE.search(message):
            severity = Severity.HIGH
        elif OOM_RE.search(message):
            severity = Severity.CRITICAL
        elif PULL_FAIL_RE.search(message):
            severity = Severity.MEDIUM
        elif PORT_CONFLICT_RE.search(message):
            severity = Severity.HIGH
        elif CRASH_RE.search(message):
            severity = Severity.CRITICAL

        # Default to medium if line looks like an error/warning
        msg_lower = message.lower()
        if severity == Severity.LOW:
            if any(w in msg_lower for w in ("error", "err]", "fatal", "panic")):
                severity = Severity.HIGH
            elif "warn" in msg_lower:
                severity = Severity.MEDIUM

        return LogEvent(
            timestamp=ts,
            level="container",
            source=source,
            message=message,
            category="docker",
            severity=severity,
            line_number=line_number,
            raw_line=line,
        )

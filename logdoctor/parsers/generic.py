"""Generic plain-text log parser."""

from __future__ import annotations

import re

from logdoctor.models import LogEvent, LogType, Severity
from logdoctor.parsers.base import BaseParser
from logdoctor.utils.time_utils import parse_auto

LEVEL_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"\b(FATAL|PANIC)\b", re.I), "FATAL", Severity.CRITICAL),
    (re.compile(r"\b(CRITICAL)\b", re.I), "CRITICAL", Severity.CRITICAL),
    (re.compile(r"\b(ERROR|ERR)\b", re.I), "ERROR", Severity.HIGH),
    (re.compile(r"\b(WARN(?:ING)?)\b", re.I), "WARNING", Severity.MEDIUM),
    (re.compile(r"\b(INFO)\b", re.I), "INFO", Severity.LOW),
    (re.compile(r"\b(DEBUG|DBG)\b", re.I), "DEBUG", Severity.LOW),
    (
        re.compile(r"\b(SEGMENTATION.?FAULT|SEGFAULT|SIGSEGV)\b", re.I),
        "CRITICAL",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"\b(Permission.?denied|ACCESS.?DENIED)\b", re.I),
        "ERROR",
        Severity.HIGH,
    ),
    (
        re.compile(r"\b(no.?space.?left|disk.?full)\b", re.I),
        "ERROR",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"\b(out.?of.?memory|OOM)\b", re.I),
        "ERROR",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"\b(connection.?refused|ECONNREFUSED)\b", re.I),
        "ERROR",
        Severity.HIGH,
    ),
    (
        re.compile(r"\b(timeout|timed.?out)\b", re.I),
        "WARNING",
        Severity.MEDIUM,
    ),
    (
        re.compile(
            r"\b(authentication.?failed|auth.?fail|access.?denied)\b", re.I,
        ),
        "ERROR",
        Severity.HIGH,
    ),
    (
        re.compile(r"\b(database.?connection.?fail)\b", re.I),
        "ERROR",
        Severity.HIGH,
    ),
    (
        re.compile(r"\b(service.?failed|failed.?to.?start)\b", re.I),
        "ERROR",
        Severity.HIGH,
    ),
    (
        re.compile(
            r"\b(import.?error|ModuleNotFoundError)\b", re.I,
        ),
        "ERROR",
        Severity.MEDIUM,
    ),
]


class GenericParser(BaseParser):
    """Parse any plain-text log file using heuristic level detection."""

    log_type = LogType.GENERIC

    def parse_line(self, line: str, line_number: int) -> LogEvent | None:
        if not line.strip():
            return None

        ts = parse_auto(line)
        level = ""
        severity = Severity.LOW
        matched = False

        for pattern, lvl, sev in LEVEL_PATTERNS:
            if pattern.search(line):
                level = lvl
                severity = sev
                matched = True
                break

        if not matched:
            return None

        return LogEvent(
            timestamp=ts,
            level=level,
            source="generic",
            message=line.strip(),
            category="generic",
            severity=severity,
            line_number=line_number,
            raw_line=line,
        )

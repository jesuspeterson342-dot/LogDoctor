"""Parser for Python traceback logs."""

from __future__ import annotations

import re

from logdoctor.models import LogEvent, LogType, Severity
from logdoctor.parsers.base import BaseParser
from logdoctor.utils.time_utils import parse_python_time

# Python log line with timestamp and level:
# 2024-01-15 03:22:11,123 - mymodule - ERROR - Something failed
PYTHON_LOG_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+"
    r"-\s+(?P<source>\S+)\s+-\s+"
    r"(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+-\s+"
    r"(?P<message>.+)"
)

# Traceback header
TRACEBACK_HEADER_RE = re.compile(r"^Traceback \(most recent call last\):")

# File line in traceback
TB_FILE_RE = re.compile(r'^\s+File "(?P<file>.+)", line (?P<line>\d+)(?:, in (?P<func>\S+))?')

# Exception line
TB_EXCEPTION_RE = re.compile(r"^(?P<type>\w+(?:\.\w+)*):?\s*(?P<message>.*)?")

LEVEL_MAP = {
    "DEBUG": "low",
    "INFO": "low",
    "WARNING": "medium",
    "ERROR": "high",
    "CRITICAL": "critical",
}


class PythonTracebackParser(BaseParser):
    """Parse Python traceback and log output."""

    log_type = LogType.PYTHON_TRACEBACK

    def __init__(self) -> None:
        self._in_traceback = False
        self._traceback_lines: list[str] = []

    def parse_line(self, line: str, line_number: int) -> LogEvent | None:
        # Check for structured Python log line
        m = PYTHON_LOG_RE.match(line)
        if m:
            level_str = m.group("level")
            severity = Severity(LEVEL_MAP.get(level_str, "medium"))
            ts = parse_python_time(m.group("timestamp"))
            return LogEvent(
                timestamp=ts,
                level=level_str,
                source=m.group("source"),
                message=m.group("message"),
                category="python_log",
                severity=severity,
                line_number=line_number,
                raw_line=line,
            )

        # Detect traceback start
        if TRACEBACK_HEADER_RE.match(line):
            self._in_traceback = True
            self._traceback_lines = [line]
            return LogEvent(
                level="ERROR",
                source="python",
                message="Python traceback detected",
                category="python_traceback",
                severity=Severity.HIGH,
                line_number=line_number,
                raw_line=line,
            )

        # Inside traceback block
        if self._in_traceback:
            self._traceback_lines.append(line)
            file_match = TB_FILE_RE.match(line)
            if file_match:
                func = file_match.group("func") or "<module>"
                fname = file_match.group("file")
                fline = file_match.group("line")
                return LogEvent(
                    level="ERROR",
                    source="python",
                    message=f'In "{fname}" line {fline} in {func}',
                    category="python_traceback",
                    severity=Severity.HIGH,
                    line_number=line_number,
                    raw_line=line,
                )
            exc_match = TB_EXCEPTION_RE.match(line.strip())
            if exc_match and not line.startswith(" "):
                self._in_traceback = False
                exc_type = exc_match.group("type")
                exc_msg = exc_match.group("message") or ""
                return LogEvent(
                    level="ERROR",
                    source="python",
                    message=f"{exc_type}: {exc_msg}".strip(),
                    category="python_exception",
                    severity=Severity.CRITICAL,
                    line_number=line_number,
                    raw_line=line,
                )
            # End of traceback on blank line
            if not line.strip():
                self._in_traceback = False

        return None

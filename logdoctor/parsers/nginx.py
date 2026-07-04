"""Parsers for nginx access and error logs."""

from __future__ import annotations

import re

from logdoctor.models import LogEvent, LogType
from logdoctor.parsers.base import BaseParser
from logdoctor.utils.time_utils import parse_nginx_time

# Nginx error log pattern:
# 2024/01/15 03:22:11 [error] 12345#0: *67890 ...
NGINX_ERROR_RE = re.compile(
    r"(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>\w+)\]\s+"
    r"(?P<pid>\d+#\d+):\s+"
    r"(?:\*\d+\s+)?"
    r"(?P<message>.+)"
)

# Nginx access log (combined format):
# 127.0.0.1 - frank [15/Jan/2024:03:22:11 +0000] "GET /api HTTP/1.1" 200 1234 "..." "..."
NGINX_ACCESS_RE = re.compile(
    r'(?P<remote>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)'
)

ERROR_LEVELS = {"error", "crit", "alert", "emerg"}
WARNING_LEVELS = {"warn"}


class NginxErrorParser(BaseParser):
    """Parse nginx error logs."""

    log_type = LogType.NGINX_ERROR

    def parse_line(self, line: str, line_number: int) -> LogEvent | None:
        m = NGINX_ERROR_RE.match(line)
        if not m:
            return None

        level_str = m.group("level").lower()
        severity_map = {
            "emerg": "critical",
            "alert": "critical",
            "crit": "critical",
            "error": "high",
            "warn": "medium",
            "notice": "low",
            "info": "low",
        }
        from logdoctor.models import Severity

        sev_str = severity_map.get(level_str, "medium")
        severity = Severity(sev_str)

        ts = parse_nginx_time(m.group("timestamp"))

        return LogEvent(
            timestamp=ts,
            level=m.group("level"),
            source="nginx",
            message=m.group("message"),
            category="nginx_error",
            severity=severity,
            line_number=line_number,
            raw_line=line,
        )


class NginxAccessParser(BaseParser):
    """Parse nginx access logs (combined format)."""

    log_type = LogType.NGINX_ACCESS

    def parse_line(self, line: str, line_number: int) -> LogEvent | None:
        m = NGINX_ACCESS_RE.match(line)
        if not m:
            return None

        status = int(m.group("status"))
        from logdoctor.models import Severity

        if status >= 500:
            severity = Severity.HIGH
        elif status >= 400:
            severity = Severity.MEDIUM
        elif status >= 300:
            severity = Severity.LOW
        else:
            severity = Severity.LOW

        ts = parse_nginx_time(m.group("timestamp"))
        method = m.group("method")
        path = m.group("path")

        return LogEvent(
            timestamp=ts,
            level=str(status),
            source="nginx",
            message=f"{method} {path} → {status}",
            category="nginx_access",
            severity=severity,
            line_number=line_number,
            raw_line=line,
        )

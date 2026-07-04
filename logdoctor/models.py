"""Data models for LogDoctor events and scan results."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Severity level for detected log events."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogType(StrEnum):
    """Supported log file types."""

    NGINX_ACCESS = "nginx_access"
    NGINX_ERROR = "nginx_error"
    PYTHON_TRACEBACK = "python_traceback"
    DOCKER = "docker"
    SYSTEMD = "systemd"
    PACMAN = "pacman"
    GENERIC = "generic"


class LogEvent(BaseModel):
    """A single detected event from a log file."""

    timestamp: datetime | None = None
    level: str = ""
    source: str = ""
    message: str = ""
    category: str = ""
    severity: Severity = Severity.LOW
    rule_id: str = ""
    line_number: int = 0
    raw_line: str = ""


class TopPattern(BaseModel):
    """A repeated pattern found during scanning."""

    pattern_id: str
    name: str
    count: int
    severity: Severity
    description: str = ""
    recommendation: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ScanResult(BaseModel):
    """Aggregated result of a log file scan."""

    file_path: str
    log_type: LogType
    total_lines: int = 0
    matched_events: list[LogEvent] = Field(default_factory=list)
    errors_count: int = 0
    warnings_count: int = 0
    critical_count: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: float = 0.0
    top_patterns: list[TopPattern] = Field(default_factory=list)


class Rule(BaseModel):
    """A detection rule loaded from YAML."""

    id: str
    name: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    category: str = ""
    description: str = ""
    recommendation: str = ""
    log_types: list[str] = Field(default_factory=list)


class AppConfig(BaseModel):
    """Application configuration."""

    default_output_format: str = "markdown"
    color: bool = True
    max_events: int = 1000
    rules_path: str = ""
    cache_dir: str = ""
    ignored_patterns: list[str] = Field(default_factory=list)

"""Log file scanning engine."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from logdoctor.detector import build_top_patterns, compile_rules, load_rules, match_line
from logdoctor.models import AppConfig, LogEvent, LogType, ScanResult, Severity
from logdoctor.parsers import detect_parser_for_file, get_parser
from logdoctor.utils.time_utils import parse_auto


def scan_file(
    filepath: str,
    config: AppConfig,
    log_type: LogType | None = None,
    on_progress: Callable[[int], None] | None = None,
) -> ScanResult:
    """Scan a log file and return aggregated results.

    Args:
        filepath: Path to the log file.
        config: Application configuration.
        log_type: Force a specific log type, or None for auto-detection.
        on_progress: Optional callback receiving line count as scanning progresses.

    Returns:
        ScanResult with all detected events and statistics.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    started_at = datetime.now()

    # Determine parser
    parser = get_parser(log_type) if log_type else detect_parser_for_file(filepath)
    detected_type = parser.log_type

    # Load and compile rules
    rules = load_rules(config)
    compiled = compile_rules(rules)

    events: list[LogEvent] = []
    rule_counter: Counter[str] = Counter()
    timestamps: list[datetime] = []
    line_count = 0

    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line_count += 1
            line = raw_line.rstrip("\n\r")

            # Parse line through parser
            event = parser.parse_line(line, line_count)

            # Match against rules
            rule_matches = match_line(line, compiled, detected_type.value)
            for rule in rule_matches:
                rule_counter[rule.id] += 1
                if event is None:
                    # Create synthetic event from rule match
                    ts = parse_auto(line)
                    event = LogEvent(
                        timestamp=ts,
                        level=rule.severity.value.upper(),
                        source="rule",
                        message=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        rule_id=rule.id,
                        line_number=line_count,
                        raw_line=line,
                    )

            if event is not None:
                events.append(event)
                if event.timestamp:
                    timestamps.append(event.timestamp)

            if on_progress and line_count % 1000 == 0:
                on_progress(line_count)

    finished_at = datetime.now()
    duration_ms = (finished_at - started_at).total_seconds() * 1000

    # Build top patterns
    top_patterns = build_top_patterns(rules, rule_counter)

    # Apply max_events limit
    if config.max_events and len(events) > config.max_events:
        events = events[: config.max_events]

    return ScanResult(
        file_path=str(path.resolve()),
        log_type=detected_type,
        total_lines=line_count,
        matched_events=events,
        errors_count=sum(1 for e in events if e.severity == Severity.HIGH),
        warnings_count=sum(1 for e in events if e.severity == Severity.MEDIUM),
        critical_count=sum(1 for e in events if e.severity == Severity.CRITICAL),
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        top_patterns=top_patterns,
    )


def scan_lines(
    lines: list[str],
    config: AppConfig,
    log_type: LogType | None = None,
) -> ScanResult:
    """Scan a list of strings as log lines. Useful for testing."""
    parser = get_parser(log_type) if log_type else get_parser(LogType.GENERIC)
    rules = load_rules(config)
    compiled = compile_rules(rules)

    events: list[LogEvent] = []
    rule_counter: Counter[str] = Counter()

    for i, line in enumerate(lines, start=1):
        event = parser.parse_line(line, i)
        rule_matches = match_line(line, compiled, parser.log_type.value)
        for rule in rule_matches:
            rule_counter[rule.id] += 1
            if event is None:
                event = LogEvent(
                    level=rule.severity.value.upper(),
                    source="rule",
                    message=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    rule_id=rule.id,
                    line_number=i,
                    raw_line=line,
                )
        if event is not None:
            events.append(event)

    top_patterns = build_top_patterns(rules, rule_counter)

    return ScanResult(
        file_path="<inline>",
        log_type=parser.log_type,
        total_lines=len(lines),
        matched_events=events,
        errors_count=sum(1 for e in events if e.severity == Severity.HIGH),
        warnings_count=sum(1 for e in events if e.severity == Severity.MEDIUM),
        critical_count=sum(1 for e in events if e.severity == Severity.CRITICAL),
        top_patterns=top_patterns,
    )

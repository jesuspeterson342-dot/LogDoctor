"""JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from logdoctor.models import ScanResult


def generate_json_report(result: ScanResult) -> str:
    """Generate a JSON report from a ScanResult."""
    data = {
        "generated_at": datetime.now().isoformat(),
        "file_path": result.file_path,
        "log_type": result.log_type.value,
        "total_lines": result.total_lines,
        "duration_ms": result.duration_ms,
        "statistics": {
            "critical": result.critical_count,
            "errors": result.errors_count,
            "warnings": result.warnings_count,
            "total_events": len(result.matched_events),
        },
        "top_patterns": [
            {
                "id": p.pattern_id,
                "name": p.name,
                "severity": p.severity.value,
                "count": p.count,
                "description": p.description,
                "recommendation": p.recommendation,
            }
            for p in result.top_patterns
        ],
        "events": [
            {
                "line_number": e.line_number,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "level": e.level,
                "severity": e.severity.value,
                "source": e.source,
                "category": e.category,
                "message": e.message,
                "rule_id": e.rule_id,
            }
            for e in result.matched_events
        ],
    }

    return json.dumps(data, indent=2, ensure_ascii=False, default=str)

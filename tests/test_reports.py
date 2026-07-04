"""Tests for report generation."""

from __future__ import annotations

import json
from pathlib import Path

from logdoctor.config import load_config
from logdoctor.output.json_report import generate_json_report
from logdoctor.output.markdown import generate_markdown_report
from logdoctor.scanner import scan_file

FIXTURES = Path(__file__).parent / "fixtures"


class TestMarkdownReport:
    """Test markdown report generation."""

    def test_generate_markdown(self) -> None:
        config = load_config()
        result = scan_file(str(FIXTURES / "nginx-error.log"), config)
        report = generate_markdown_report(result)

        assert "# LogDoctor Report" in report
        assert "nginx" in report.lower()
        assert "Summary" in report
        assert "Top Patterns" in report

    def test_markdown_has_statistics(self) -> None:
        config = load_config()
        result = scan_file(str(FIXTURES / "docker.log"), config)
        report = generate_markdown_report(result)

        assert "Critical" in report
        assert "Errors" in report
        assert "Warnings" in report

    def test_markdown_recommendations(self) -> None:
        config = load_config()
        result = scan_file(str(FIXTURES / "nginx-error.log"), config)
        report = generate_markdown_report(result)

        if result.top_patterns:
            assert "Recommendations" in report


class TestJsonReport:
    """Test JSON report generation."""

    def test_generate_json(self) -> None:
        config = load_config()
        result = scan_file(str(FIXTURES / "nginx-error.log"), config)
        report = generate_json_report(result)

        data = json.loads(report)
        assert "generated_at" in data
        assert "statistics" in data
        assert "events" in data
        assert "top_patterns" in data

    def test_json_structure(self) -> None:
        config = load_config()
        result = scan_file(str(FIXTURES / "python-traceback.log"), config)
        report = generate_json_report(result)
        data = json.loads(report)

        assert isinstance(data["events"], list)
        assert isinstance(data["top_patterns"], list)
        assert isinstance(data["statistics"], dict)
        assert data["statistics"]["critical"] >= 0
        assert data["statistics"]["errors"] >= 0
        assert data["statistics"]["warnings"] >= 0

    def test_json_events_have_fields(self) -> None:
        config = load_config()
        result = scan_file(str(FIXTURES / "docker.log"), config)
        report = generate_json_report(result)
        data = json.loads(report)

        for event in data["events"]:
            assert "line_number" in event
            assert "severity" in event
            assert "message" in event
            assert "category" in event


class TestReportEdgeCases:
    """Test report generation with edge cases."""

    def test_empty_file_report(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.log"
        empty.write_text("")
        config = load_config()
        result = scan_file(str(empty), config)

        md = generate_markdown_report(result)
        assert "# LogDoctor Report" in md

        js = generate_json_report(result)
        data = json.loads(js)
        assert data["total_lines"] == 0
        assert len(data["events"]) == 0

    def test_report_with_forced_type(self) -> None:
        config = load_config()
        result = scan_file(str(FIXTURES / "nginx-error.log"), config)
        report = generate_json_report(result)
        data = json.loads(report)
        assert data["log_type"] == "nginx_error"

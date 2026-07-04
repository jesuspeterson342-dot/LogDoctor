"""Tests for scanner and log type detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from logdoctor.config import load_config
from logdoctor.models import LogType
from logdoctor.parsers import detect_parser_for_file
from logdoctor.parsers.base import detect_log_type
from logdoctor.scanner import scan_file, scan_lines

FIXTURES = Path(__file__).parent / "fixtures"


class TestLogTypeDetection:
    """Test log type auto-detection."""

    def test_detect_nginx_error(self) -> None:
        log_type = detect_log_type(str(FIXTURES / "nginx-error.log"))
        assert log_type == LogType.NGINX_ERROR

    def test_detect_python_traceback(self) -> None:
        log_type = detect_log_type(str(FIXTURES / "python-traceback.log"))
        assert log_type == LogType.PYTHON_TRACEBACK

    def test_detect_docker(self) -> None:
        log_type = detect_log_type(str(FIXTURES / "docker.log"))
        assert log_type == LogType.DOCKER

    def test_detect_pacman(self) -> None:
        log_type = detect_log_type(str(FIXTURES / "pacman.log"))
        assert log_type == LogType.PACMAN

    def test_detect_nonexistent_file(self) -> None:
        log_type = detect_log_type("/nonexistent/file.log")
        assert log_type == LogType.GENERIC

    def test_parser_detection_matches(self) -> None:
        parser = detect_parser_for_file(str(FIXTURES / "nginx-error.log"))
        assert parser.log_type == LogType.NGINX_ERROR


class TestScanner:
    """Test the scan_file function."""

    def setup_method(self) -> None:
        self.config = load_config()

    def test_scan_nginx_error(self) -> None:
        result = scan_file(str(FIXTURES / "nginx-error.log"), self.config)
        assert result.log_type == LogType.NGINX_ERROR
        assert result.total_lines == 6
        assert len(result.matched_events) > 0

    def test_scan_python_traceback(self) -> None:
        result = scan_file(str(FIXTURES / "python-traceback.log"), self.config)
        assert result.log_type == LogType.PYTHON_TRACEBACK
        assert result.total_lines == 13
        assert len(result.matched_events) > 0

    def test_scan_docker(self) -> None:
        result = scan_file(str(FIXTURES / "docker.log"), self.config)
        assert result.log_type == LogType.DOCKER
        assert result.total_lines == 8
        assert len(result.matched_events) > 0

    def test_scan_pacman(self) -> None:
        result = scan_file(str(FIXTURES / "pacman.log"), self.config)
        assert result.log_type == LogType.PACMAN
        assert result.total_lines == 8

    def test_scan_nonexistent_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            scan_file("/nonexistent/file.log", self.config)

    def test_scan_empty_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.log"
        empty.write_text("")
        result = scan_file(str(empty), self.config)
        assert result.total_lines == 0
        assert len(result.matched_events) == 0

    def test_scan_has_timestamps(self) -> None:
        result = scan_file(str(FIXTURES / "nginx-error.log"), self.config)
        assert result.started_at is not None
        assert result.finished_at is not None

    def test_scan_severity_counts(self) -> None:
        result = scan_file(str(FIXTURES / "nginx-error.log"), self.config)
        # nginx error log should have some high/critical severity events
        assert result.errors_count + result.critical_count > 0

    def test_scan_lines_inline(self) -> None:
        lines = [
            (
                "2024/01/15 03:22:11 [error] 12345#0: "
                "*67890 connect() failed (111: Connection refused)"
            ),
            "2024/01/15 03:22:12 [error] 12345#0: *67891 upstream timed out",
            "normal line without anything",
        ]
        result = scan_lines(lines, self.config, log_type=LogType.NGINX_ERROR)
        assert result.total_lines == 3
        assert len(result.matched_events) > 0


class TestScanWithForcedType:
    """Test scanning with forced log type."""

    def setup_method(self) -> None:
        self.config = load_config()

    def test_forced_nginx_type(self) -> None:
        result = scan_file(
            str(FIXTURES / "nginx-error.log"), self.config, log_type=LogType.NGINX_ERROR
        )
        assert result.log_type == LogType.NGINX_ERROR

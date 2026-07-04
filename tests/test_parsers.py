"""Tests for individual log parsers."""

from __future__ import annotations

from logdoctor.models import LogType, Severity
from logdoctor.parsers import get_parser
from logdoctor.parsers.docker import DockerParser
from logdoctor.parsers.generic import GenericParser
from logdoctor.parsers.nginx import NginxAccessParser, NginxErrorParser
from logdoctor.parsers.pacman import PacmanParser
from logdoctor.parsers.python_traceback import PythonTracebackParser


class TestNginxErrorParser:
    """Test nginx error log parsing."""

    def test_parse_error_line(self) -> None:
        parser = NginxErrorParser()
        line = (
            "2024/01/15 03:22:11 [error] 12345#0: "
            "*67890 connect() failed (111: Connection refused)"
        )
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.HIGH
        assert event.source == "nginx"
        assert "Connection refused" in event.message
        assert event.timestamp is not None

    def test_parse_crit_line(self) -> None:
        parser = NginxErrorParser()
        line = "2024/01/15 03:22:11 [crit] 12345#0: something critical"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.CRITICAL

    def test_parse_emerg_line(self) -> None:
        parser = NginxErrorParser()
        line = "2024/01/15 03:22:11 [emerg] 12345#0: emergency"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.CRITICAL

    def test_skip_non_error(self) -> None:
        parser = NginxErrorParser()
        event = parser.parse_line("just a random line", 1)
        assert event is None


class TestNginxAccessParser:
    """Test nginx access log parsing."""

    def test_parse_200(self) -> None:
        parser = NginxAccessParser()
        line = (
            '192.168.1.1 - - [15/Jan/2024:03:22:11 +0000] '
            '"GET /api HTTP/1.1" 200 1234 "-" "curl"'
        )
        event = parser.parse_line(line, 1)
        assert event is not None
        assert "200" in event.level
        assert "GET /api" in event.message

    def test_parse_500(self) -> None:
        parser = NginxAccessParser()
        line = '10.0.0.1 - - [15/Jan/2024:03:22:11 +0000] "POST /api HTTP/1.1" 500 50 "-" "python"'
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.HIGH


class TestPythonTracebackParser:
    """Test Python traceback log parsing."""

    def test_parse_log_line(self) -> None:
        parser = PythonTracebackParser()
        line = "2024-01-15 03:22:11,123 - myapp.auth - ERROR - Auth failed"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.HIGH
        assert event.source == "myapp.auth"

    def test_parse_traceback_header(self) -> None:
        parser = PythonTracebackParser()
        event = parser.parse_line("Traceback (most recent call last):", 1)
        assert event is not None
        assert event.category == "python_traceback"

    def test_parse_exception_line(self) -> None:
        parser = PythonTracebackParser()
        # Start traceback
        parser.parse_line("Traceback (most recent call last):", 1)
        parser.parse_line('  File "app.py", line 10', 2)
        event = parser.parse_line("ValueError: invalid value", 3)
        assert event is not None
        assert "ValueError" in event.message
        assert event.severity == Severity.CRITICAL


class TestDockerParser:
    """Test Docker log parsing."""

    def test_parse_container_exit(self) -> None:
        parser = DockerParser()
        line = "2024-01-15T03:22:11.123456789Z web-app-1  Container exited with code 137"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.HIGH
        assert event.source == "web-app-1"

    def test_parse_oom(self) -> None:
        parser = DockerParser()
        line = "2024-01-15T03:22:11.123456789Z worker-1  Out of memory: Killed process"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.CRITICAL

    def test_parse_normal_line(self) -> None:
        parser = DockerParser()
        line = "2024-01-15T03:22:11.123456789Z web-app-1  Starting application"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.LOW


class TestPacmanParser:
    """Test pacman log parsing."""

    def test_parse_install(self) -> None:
        parser = PacmanParser()
        line = "[2024-01-15T03:22:11+0000] [ALPM] upgraded linux (6.6.10.arch1-1 -> 6.6.11.arch1-1)"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.category == "pacman"

    def test_parse_keyring_error(self) -> None:
        parser = PacmanParser()
        line = "[2024-01-15T03:22:11+0000] [ALPM] warning: key unknown trust"
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity == Severity.HIGH


class TestGenericParser:
    """Test generic log parsing."""

    def test_parse_error_line(self) -> None:
        parser = GenericParser()
        event = parser.parse_line("ERROR something went wrong", 1)
        assert event is not None
        assert event.severity == Severity.HIGH

    def test_parse_empty_line(self) -> None:
        parser = GenericParser()
        event = parser.parse_line("", 1)
        assert event is None

    def test_parse_normal_line(self) -> None:
        parser = GenericParser()
        event = parser.parse_line("everything is fine", 1)
        assert event is None


class TestParserRegistration:
    """Test parser factory functions."""

    def test_get_nginx_error_parser(self) -> None:
        parser = get_parser(LogType.NGINX_ERROR)
        assert isinstance(parser, NginxErrorParser)

    def test_get_nginx_access_parser(self) -> None:
        parser = get_parser(LogType.NGINX_ACCESS)
        assert isinstance(parser, NginxAccessParser)

    def test_get_python_parser(self) -> None:
        parser = get_parser(LogType.PYTHON_TRACEBACK)
        assert isinstance(parser, PythonTracebackParser)

    def test_get_docker_parser(self) -> None:
        parser = get_parser(LogType.DOCKER)
        assert isinstance(parser, DockerParser)

    def test_get_pacman_parser(self) -> None:
        parser = get_parser(LogType.PACMAN)
        assert isinstance(parser, PacmanParser)

    def test_get_generic_parser(self) -> None:
        parser = get_parser(LogType.GENERIC)
        assert isinstance(parser, GenericParser)

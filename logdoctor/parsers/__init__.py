"""Log parsers for various log formats."""

from __future__ import annotations

from logdoctor.models import LogType
from logdoctor.parsers.base import BaseParser
from logdoctor.parsers.docker import DockerParser
from logdoctor.parsers.generic import GenericParser
from logdoctor.parsers.nginx import NginxAccessParser, NginxErrorParser
from logdoctor.parsers.pacman import PacmanParser
from logdoctor.parsers.python_traceback import PythonTracebackParser

PARSER_MAP: dict[LogType, type[BaseParser]] = {}


def register_parser(log_type: LogType, parser_cls: type[BaseParser]) -> None:
    """Register a parser class for a log type."""
    PARSER_MAP[log_type] = parser_cls


def get_parser(log_type: LogType) -> BaseParser:
    """Get a parser instance for the given log type."""
    if log_type in PARSER_MAP:
        return PARSER_MAP[log_type]()
    return GenericParser()


def detect_parser_for_file(filepath: str) -> BaseParser:
    """Auto-detect the best parser for a file based on content sniffing."""
    from logdoctor.parsers.base import detect_log_type

    log_type = detect_log_type(filepath)
    return get_parser(log_type)


register_parser(LogType.NGINX_ERROR, NginxErrorParser)
register_parser(LogType.NGINX_ACCESS, NginxAccessParser)
register_parser(LogType.PYTHON_TRACEBACK, PythonTracebackParser)
register_parser(LogType.DOCKER, DockerParser)
register_parser(LogType.PACMAN, PacmanParser)
register_parser(LogType.GENERIC, GenericParser)

__all__ = [
    "BaseParser",
    "NginxErrorParser",
    "NginxAccessParser",
    "PythonTracebackParser",
    "DockerParser",
    "PacmanParser",
    "GenericParser",
    "get_parser",
    "detect_parser_for_file",
    "register_parser",
]

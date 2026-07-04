#!/usr/bin/env python3
"""Generate a large synthetic log file for benchmarking LogDoctor."""

import argparse
import random
import sys
from datetime import datetime, timedelta

ERROR_MESSAGES = [
    "connect() failed (111: Connection refused) while connecting to upstream",
    "upstream timed out (110: Connection timed out) while reading response header",
    "Permission denied: /var/www/html",
    "No space left on device",
    "Out of memory: Killed process 12345 (java)",
    "Segmentation fault (core dumped)",
    "connection refused to 127.0.0.1:5432",
    "authentication failed for user admin",
    "database connection failed: timeout after 30s",
    "service nginx failed to start",
    "502 Bad Gateway",
    "504 Gateway Timeout",
    "SSL_do_handshake() failed",
    "worker connections are not enough",
    "Traceback (most recent call last): ImportError: No module named 'requests'",
    "panic: runtime error: index out of range",
    "FATAL: could not open file \"pg_hba.conf\"",
    "Container exited with code 137",
    "Port 8080 already in use",
    "failed to commit transaction (conflicting files)",
]

WARNING_MESSAGES = [
    "upstream server returned 502",
    "connection reset by peer",
    "dependency cycle detected",
    "key unknown trust",
    "database connection slow (2340ms)",
    "retrying request in 5s",
    "deprecated config option detected",
    "cache miss ratio high: 78%",
]

INFO_MESSAGES = [
    "GET /api/health 200 1234",
    "POST /api/users 201 5678",
    "started worker process 12345",
    "listening on port 80",
    "upstream connected successfully",
    "configuration reloaded",
    "connection pool established (size=10)",
    "background task completed",
    "session started for user 42",
    "request handled in 45ms",
]

CRITICAL_MESSAGES = [
    "FATAL: too many connections to database",
    "EMERG: system is going down for power off",
    "CRITICAL: disk space below 1%",
    "Out of memory: system unstable",
]

LEVELS_AND_WEIGHTS = [
    ("INFO", INFO_MESSAGES, 60),
    ("WARNING", WARNING_MESSAGES, 20),
    ("ERROR", ERROR_MESSAGES, 15),
    ("CRITICAL", CRITICAL_MESSAGES, 5),
]


def generate_log(lines: int, output: str) -> None:
    """Write lines random synthetic log entries to output file."""
    levels, _messages, weights = zip(*LEVELS_AND_WEIGHTS, strict=True)
    start_time = datetime(2025, 1, 15, 0, 0, 0)

    with open(output, "w", encoding="utf-8") as fh:
        for i in range(lines):
            ts = start_time + timedelta(seconds=i * 2 + random.randint(0, 3))
            level = random.choices(levels, weights=weights, k=1)[0]
            msg_pool = {
                "INFO": INFO_MESSAGES,
                "WARNING": WARNING_MESSAGES,
                "ERROR": ERROR_MESSAGES,
                "CRITICAL": CRITICAL_MESSAGES,
            }
            message = random.choice(msg_pool[level])
            fh.write(
                f"{ts.strftime('%Y-%m-%d %H:%M:%S')} [{level:<8}] {message}\n"
            )

    print(f"Generated {lines:,} lines -> {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic log for benchmarking")
    parser.add_argument(
        "--lines", type=int, default=100_000, help="Number of lines to generate (default: 100000)",
    )
    parser.add_argument(
        "--output", type=str, default="examples/big.log", help="Output file path",
    )
    args = parser.parse_args()

    if args.lines <= 0:
        print("Error: --lines must be positive", file=sys.stderr)
        sys.exit(1)

    generate_log(args.lines, args.output)


if __name__ == "__main__":
    main()

# LogDoctor

[![CI](https://github.com/jesuspeterson342-dot/logdoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/jesuspeterson342-dot/logdoctor/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-56%20passed-brightgreen)]()
[![Ruff](https://img.shields.io/badge/ruff-passing-brightgreen)]()
[![mypy](https://img.shields.io/badge/mypy-strict-brightgreen)]()

> **Terminal utility for log analysis, error detection, and reporting.**

LogDoctor parses log files, detects errors and anomalies using regex-based rules, groups repeating patterns, and generates structured reports in Markdown or JSON. Built for DevOps engineers and Linux developers who live in the terminal.

---

### Scan Result

| Property | Value |
|:---------|------:|
| **File** | `/var/log/nginx/error.log` |
| **Type** | `nginx_error` |
| **Lines** | `14,892` |
| **Duration** | `23ms` |
| **Critical** | `0` |
| **Errors** | `12` |
| **Warnings** | `3` |

### Top Patterns

| Rule | Severity | Count | Description |
|:-----|:--------:|------:|:------------|
| Connection refused | `▲ HIGH` | 8 | Upstream unreachable |
| Upstream timeout | `▲ HIGH` | 4 | Backend did not respond in time |
| SSL error | `▲ HIGH` | 2 | TLS handshake failed |

---

## Why This Project Exists

When a production service goes down at 3 AM, the first thing you do is read the logs. But logs grow fast — thousands of lines of noise hiding the one line that matters. Manually grepping through them is slow and error-prone.

LogDoctor solves this: point it at a log file, and it instantly identifies error patterns, groups them by frequency, assigns severity levels, and tells you what to fix. No configuration needed for common formats — it auto-detects nginx, Python, Docker, and pacman logs.

---

## Features

- **Auto-detection** of log types (nginx, Python, Docker, pacman, systemd, generic)
- **Regex-based rules** engine with YAML-defined patterns
- **7 CLI commands**: `scan`, `watch`, `report`, `rules`, `doctor`, `benchmark`, `init`
- **Rich terminal UI** with colored severity labels, tables, panels
- **Multiple output formats**: Markdown, JSON, plain text
- **Real-time monitoring** with `watch` (`tail -f` with intelligence)
- **Performance benchmarking** for large log files
- **35 built-in rules** covering common failure scenarios
- **Configurable** via `~/.config/logdoctor/config.yml`

---

## Demo

### Scan a log file

```bash
$ logdoctor scan examples/nginx-error.log
```

| Property | Value |
|:---------|------:|
| **File** | `examples/nginx-error.log` |
| **Type** | `nginx_error` |
| **Lines** | `6` |
| **Duration** | `27ms` |
| **Critical** | `1` |
| **Errors** | `4` |
| **Warnings** | `1` |

#### Top Patterns

| Rule | Severity | Count | Description |
|:-----|:--------:|------:|:------------|
| Connection refused | `▲ HIGH` | 1 | Upstream unreachable |
| Nginx connection refused | `▲ HIGH` | 1 | Backend unreachable |
| Connection/request timeout | `◆ MEDIUM` | 1 | Request timed out |
| Gateway timeout (504) | `▲ HIGH` | 1 | Backend too slow |
| Bad gateway (502) | `▲ HIGH` | 1 | Invalid upstream resp |
| SSL/TLS error | `▲ HIGH` | 1 | TLS handshake failed |
| Connection reset by peer | `◆ MEDIUM` | 1 | Peer disconnected |

### Benchmark on a large file

```bash
$ python scripts/generate_big_log.py --lines 100000 --output examples/big.log
Generated 100,000 lines -> examples/big.log

$ logdoctor benchmark examples/big.log
```

#### Benchmark Result

| Metric | Value |
|:-------|------:|
| **File** | `examples/big.log` |
| **Total lines** | `100,000` |
| **Events found** | `35,000` |
| **Elapsed time** | `850ms` |
| **Lines/second** | `117,647` |
| **Memory peak** | `2.1 MB` |

---

## Installation

```bash
# Via pipx (recommended)
pipx install .

# Via pip (development)
pip install -e ".[dev]"
```

---

## Usage

### Scan a log file

```bash
# Auto-detect log type
logdoctor scan /var/log/nginx/error.log

# Force specific log type
logdoctor scan app.log --type python_traceback

# JSON output
logdoctor scan app.log --format json

# Save to file
logdoctor scan app.log --output result.md
```

### Watch in real-time

```bash
# Follow log with smart highlighting
logdoctor watch /var/log/pacman.log

# Force log type
logdoctor watch /var/log/syslog --type systemd
```

### Generate reports

```bash
# Markdown report
logdoctor report app.log --format markdown --output report.md

# JSON report
logdoctor report app.log --format json --output report.json

# Plain text
logdoctor report app.log --format text --output report.txt
```

### List rules

```bash
logdoctor rules list
```

### Environment check

```bash
logdoctor doctor
```

### Benchmark performance

```bash
# Generate a test file
python scripts/generate_big_log.py --lines 100000 --output big.log

# Run benchmark
logdoctor benchmark big.log
```

---

## CLI Reference

| Command | Description |
|:--------|:------------|
| `logdoctor scan <file>` | Analyze a log file for errors |
| `logdoctor watch <file>` | Monitor a log in real-time |
| `logdoctor report <file>` | Generate a structured report |
| `logdoctor rules list` | Show active analysis rules |
| `logdoctor doctor` | Check environment and config |
| `logdoctor benchmark <file>` | Test scanning performance |
| `logdoctor init` | Create default config and rules |

### Global Options

| Option | Description |
|:-------|:------------|
| `--color / --no-color` | Toggle colored output |
| `--quiet, -q` | Suppress non-essential output |
| `--verbose, -v` | Show detailed output |
| `--version, -V` | Show version |

---

## Supported Log Types

| Type | Format | Example |
|:-----|:-------|:--------|
| `nginx_error` | Nginx error log with timestamps | `[error] connect() failed` |
| `nginx_access` | Nginx combined access log | `127.0.0.1 - - [15/Jan/...]` |
| `python_traceback` | Python logs + tracebacks | `Traceback (most recent call last):` |
| `docker` | Docker Compose log output | `2024-01-15T03:22:11Z container msg` |
| `pacman` | Arch Linux pacman.log | `[2024-01-15T...] [ALPM] ...` |
| `systemd` | systemd journal export | syslog-style format |
| `generic` | Any plain text with level markers | `ERROR something failed` |

---

## Architecture

```
logdoctor/
├── __init__.py          # Package metadata
├── cli.py               # Typer CLI application
├── config.py            # YAML config loading
├── models.py            # Pydantic data models
├── scanner.py           # Core scanning engine
├── detector.py          # Rule matching engine
├── parsers/
│   ├── base.py          # Base parser + log type detection
│   ├── nginx.py         # Nginx access/error logs
│   ├── python_traceback.py  # Python tracebacks
│   ├── docker.py        # Docker Compose logs
│   ├── pacman.py        # Arch pacman.log
│   └── generic.py       # Generic text logs
├── rules/
│   ├── default_rules.yml    # General rules
│   ├── nginx_rules.yml      # Nginx-specific rules
│   ├── python_rules.yml     # Python-specific rules
│   ├── docker_rules.yml     # Docker-specific rules
│   └── pacman_rules.yml     # Pacman-specific rules
├── output/
│   ├── console.py       # Rich terminal output
│   ├── markdown.py      # Markdown report generator
│   └── json_report.py   # JSON report generator
└── utils/
    ├── file_utils.py    # File system helpers
    ├── time_utils.py    # Timestamp parsing
    └── perf.py          # Performance measurement
```

---

## Rule Format

Rules are defined in YAML files:

```yaml
- id: connection-refused
  name: Connection refused
  pattern: "(?i)connection\\s+refused|econnrefused"
  severity: high
  category: network
  description: "Target service is not listening on expected port"
  recommendation: "Verify the target service is running and listening"
  log_types: ["nginx_error", "docker"]  # optional: restrict to specific log types
```

### Rule fields

| Field | Required | Description |
|:------|:--------:|:------------|
| `id` | Yes | Unique identifier |
| `name` | Yes | Human-readable name |
| `pattern` | Yes | Python regex pattern |
| `severity` | Yes | `low` / `medium` / `high` / `critical` |
| `category` | No | Classification tag |
| `description` | No | What this means |
| `recommendation` | No | How to fix it |
| `log_types` | No | Restrict to specific log types |

---

## Configuration

Config file: `~/.config/logdoctor/config.yml`

```yaml
default_output_format: markdown
color: true
max_events: 1000
rules_path: ""        # custom rules directory (empty = bundled)
cache_dir: ""         # cache directory (empty = ~/.cache/logdoctor)
ignored_patterns: []  # patterns to skip during analysis
```

---

## Development

### Setup

```bash
git clone https://github.com/jesuspeterson342-dot/logdoctor.git
cd logdoctor
pip install -e ".[dev]"
```

### Run tests

```bash
pytest
pytest -v                    # verbose
pytest --cov=logdoctor       # with coverage
```

### Linting

```bash
ruff check .                 # lint
ruff format .                # format
mypy logdoctor               # type check
```

### Generate benchmark data

```bash
python scripts/generate_big_log.py --lines 100000 --output examples/big.log
logdoctor benchmark examples/big.log
```

### Fish shell completion

```bash
logdoctor --install-completion fish | source
```

Or manually: run `logdoctor --install-completion fish` and follow the instructions.

---

## Roadmap

- [ ] Add syslog/RSYSLOG_SyslogProtocol23 format support
- [ ] Add journald binary format parsing
- [ ] Add `logdoctor diff` command for comparing two log files
- [ ] Add custom regex rule creation via CLI
- [ ] Add `--follow` mode with reconnection support
- [ ] Add HTML report output format
- [ ] Add plugin system for custom parsers
- [ ] Performance: streaming mode for multi-GB files

---

## License

**MIT**

---

## Portfolio Value

This project demonstrates:

- **Typed Python** — full type annotations, Pydantic models, StrEnum, mypy strict mode passes clean
- **CLI architecture** — Typer-based command structure with proper help text, global options, and 7 subcommands
- **Rich terminal UI** — tables, panels, progress bars, color-coded severity labels, responsive layout
- **YAML rules engine** — 35 pre-compiled regex rules across 5 YAML files, hot-loadable from config directory
- **Log parsing** — 6 dedicated parsers with auto-detection via content sniffing (nginx, Python, Docker, pacman, systemd, generic)
- **Test coverage** — 56 pytest tests covering parsers, detectors, scanners, report generators, and edge cases
- **Packaging** — pyproject.toml with hatch build system, pipx-ready, entry points configured
- **CI** — GitHub Actions workflow running pytest, ruff, and mypy on Python 3.12 and 3.13
- **Performance benchmark** — `benchmark` command measuring lines/sec, elapsed time, and memory usage on 100K+ line files

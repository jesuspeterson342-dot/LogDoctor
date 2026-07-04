# Changelog

All notable changes to LogDoctor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-07-04

### Added

- **`scan`** — analyze log files, detect errors, group by pattern, display severity table
- **`watch`** — real-time log monitoring with color-coded severity alerts (Ctrl+C to stop)
- **`report`** — generate Markdown, JSON, or plain-text reports with statistics and recommendations
- **`rules`** — list all active detection rules with severity, category, and regex pattern
- **`doctor`** — environment health check (Python version, config, rules, cache, permissions)
- **`benchmark`** — measure scanning throughput (lines/sec, memory usage, elapsed time)
- **`init`** — create default config at `~/.config/logdoctor/config.yml` and copy bundled rules

- 35 built-in YAML rules across 5 categories:
  - `default_rules.yml` — generic errors (permission denied, OOM, segfault, disk full, etc.)
  - `nginx_rules.yml` — 502, 504, connection refused, SSL errors, worker limits
  - `python_rules.yml` — tracebacks, ImportError, TypeError, KeyError, MemoryError
  - `docker_rules.yml` — container exit, OOM kill, port conflict, volume mount errors
  - `pacman_rules.yml` — failed transactions, keyring errors, corrupt packages

- 6 log parsers with auto-detection:
  - Nginx error and access logs
  - Python tracebacks and structured log output
  - Docker Compose container logs
  - Arch Linux pacman.log
  - Generic plain-text with heuristic level detection

- Rich terminal UI with colored severity labels, tables, panels, and progress spinners
- Markdown and JSON report generation with timeline, recommendations, and pattern summary
- Configuration via `~/.config/logdoctor/config.yml` (output format, color, max events, rules path)
- Fish shell completion support
- pipx-compatible packaging via hatch/pyproject.toml

### Fixed

- Benchmark command now reports accurate elapsed time and lines/sec throughput

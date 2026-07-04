# Changelog

All notable changes to LogDoctor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2025-07-04

### Added

#### Commands

| Command | Description |
|:--------|:------------|
| `scan` | Analyze log files, detect errors, group by pattern, display severity table |
| `watch` | Real-time log monitoring with color-coded severity alerts (Ctrl+C to stop) |
| `report` | Generate Markdown, JSON, or plain-text reports with statistics and recommendations |
| `rules` | List all active detection rules with severity, category, and regex pattern |
| `doctor` | Environment health check (Python version, config, rules, cache, permissions) |
| `benchmark` | Measure scanning throughput (lines/sec, memory usage, elapsed time) |
| `init` | Create default config at `~/.config/logdoctor/config.yml` and copy bundled rules |

#### Built-in Rules

35 built-in YAML rules across 5 categories:

| Rule File | Scope |
|:----------|:------|
| `default_rules.yml` | Generic errors (permission denied, OOM, segfault, disk full, etc.) |
| `nginx_rules.yml` | 502, 504, connection refused, SSL errors, worker limits |
| `python_rules.yml` | Tracebacks, ImportError, TypeError, KeyError, MemoryError |
| `docker_rules.yml` | Container exit, OOM kill, port conflict, volume mount errors |
| `pacman_rules.yml` | Failed transactions, keyring errors, corrupt packages |

#### Log Parsers

6 log parsers with auto-detection:

| Parser | Supported Format |
|:-------|:-----------------|
| Nginx | Error and access logs |
| Python | Tracebacks and structured log output |
| Docker | Compose container logs |
| Pacman | Arch Linux pacman.log |
| Systemd | Journal export |
| Generic | Plain-text with heuristic level detection |

#### Other

- Rich terminal UI with colored severity labels, tables, panels, and progress spinners
- Markdown and JSON report generation with timeline, recommendations, and pattern summary
- Configuration via `~/.config/logdoctor/config.yml` (output format, color, max events, rules path)
- Fish shell completion support
- pipx-compatible packaging via hatch/pyproject.toml

---

### Fixed

- Benchmark command now reports accurate elapsed time and lines/sec throughput

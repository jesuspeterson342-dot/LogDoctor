"""Rule-based event detection engine."""

from __future__ import annotations

import re
from collections import Counter

import yaml

from logdoctor.config import get_rules_dir
from logdoctor.models import AppConfig, Rule, TopPattern


def load_rules(config: AppConfig) -> list[Rule]:
    """Load all YAML rule files from the rules directory."""
    rules_dir = get_rules_dir(config)
    all_rules: list[Rule] = []

    if not rules_dir.exists():
        return all_rules

    for yml_file in sorted(rules_dir.glob("*.yml")):
        try:
            raw = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        if not raw or not isinstance(raw, list):
            continue
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            try:
                rule = Rule(**entry)
                all_rules.append(rule)
            except Exception:
                continue

    return all_rules


def compile_rules(rules: list[Rule]) -> list[tuple[Rule, re.Pattern[str]]]:
    """Pre-compile rule patterns for fast matching."""
    compiled: list[tuple[Rule, re.Pattern[str]]] = []
    for rule in rules:
        try:
            pat = re.compile(rule.pattern, re.IGNORECASE)
            compiled.append((rule, pat))
        except re.error:
            continue
    return compiled


def match_line(
    line: str,
    compiled_rules: list[tuple[Rule, re.Pattern[str]]],
    log_type: str = "",
) -> list[Rule]:
    """Match a line against all compiled rules. Returns matching Rule objects."""
    matched: list[Rule] = []
    for rule, pattern in compiled_rules:
        if rule.log_types and log_type not in rule.log_types:
            continue
        if pattern.search(line):
            matched.append(rule)
    return matched


def build_top_patterns(matched_rules: list[Rule], line_counts: Counter[str]) -> list[TopPattern]:
    """Build sorted list of TopPattern from matched rules and their occurrence counts."""
    patterns: list[TopPattern] = []
    for rule_id, count in line_counts.most_common():
        for rule in matched_rules:
            if rule.id == rule_id:
                patterns.append(
                    TopPattern(
                        pattern_id=rule.id,
                        name=rule.name,
                        count=count,
                        severity=rule.severity,
                        description=rule.description,
                        recommendation=rule.recommendation,
                    )
                )
                break
    return patterns

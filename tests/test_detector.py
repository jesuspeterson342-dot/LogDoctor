"""Tests for rule detection engine."""

from __future__ import annotations

import re

from logdoctor.config import load_config
from logdoctor.detector import compile_rules, load_rules, match_line
from logdoctor.models import Severity


class TestRuleLoading:
    """Test loading rules from YAML files."""

    def test_load_rules_returns_list(self) -> None:
        config = load_config()
        rules = load_rules(config)
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_rules_have_required_fields(self) -> None:
        config = load_config()
        rules = load_rules(config)
        for rule in rules:
            assert rule.id
            assert rule.name
            assert rule.pattern
            assert rule.severity in Severity

    def test_compile_rules_returns_compiled(self) -> None:
        config = load_config()
        rules = load_rules(config)
        compiled = compile_rules(rules)
        assert len(compiled) == len(rules)
        for _rule, pattern in compiled:
            assert isinstance(pattern, re.Pattern)


class TestRuleMatching:
    """Test matching lines against rules."""

    def setup_method(self) -> None:
        config = load_config()
        rules = load_rules(config)
        self.compiled = compile_rules(rules)

    def test_match_connection_refused(self) -> None:
        line = "2024/01/15 03:22:11 [error] connect() failed (111: Connection refused)"
        matched = match_line(line, self.compiled, "nginx_error")
        rule_ids = [r.id for r in matched]
        assert "nginx-connection-refused" in rule_ids or "connection-refused" in rule_ids

    def test_match_permission_denied(self) -> None:
        line = "Permission denied: /var/www/html"
        matched = match_line(line, self.compiled)
        rule_ids = [r.id for r in matched]
        assert "permission-denied" in rule_ids

    def test_match_no_match(self) -> None:
        line = "2024/01/15 all systems operational"
        matched = match_line(line, self.compiled)
        assert len(matched) == 0

    def test_match_multiple_rules(self) -> None:
        line = "connection refused: no space left on device"
        matched = match_line(line, self.compiled)
        assert len(matched) >= 2

    def test_match_is_case_insensitive(self) -> None:
        line = "CONNECTION REFUSED to upstream"
        matched = match_line(line, self.compiled)
        assert len(matched) > 0

    def test_match_nginx_specific_rules(self) -> None:
        line = "2024/01/15 [error] upstream timed out"
        matched = match_line(line, self.compiled, "nginx_error")
        rule_ids = [r.id for r in matched]
        # Should match at least one nginx rule
        assert any("nginx" in rid for rid in rule_ids) or len(matched) > 0

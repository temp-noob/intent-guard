"""Tests for sensitive data / PII scanning in tool call arguments."""

from __future__ import annotations

import pytest

from intent_guard.sdk.engine import IntentGuardEngine

SENSITIVE_PATTERNS = [
    {"name": "AWS Access Key", "pattern": "AKIA[0-9A-Z]{16}"},
    {"name": "GitHub Token", "pattern": "gh[ps]_[A-Za-z0-9_]{36,}"},
    {
        "name": "Generic API Key",
        "pattern": "(?i)(api[_-]?key|apikey|api_secret)\\s*[=:]\\s*\\S+",
    },
    {
        "name": "Generic Secret",
        "pattern": "(?i)(password|passwd|secret|token)\\s*[=:]\\s*\\S+",
    },
    {
        "name": "Email Address",
        "pattern": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    },
    {"name": "SSN", "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b"},
]


def _engine(patterns=None):
    policy = {"static_rules": {}}
    if patterns is not None:
        policy["static_rules"]["sensitive_data_patterns"] = patterns
    return IntentGuardEngine(policy=policy)


class TestSensitiveDataScanning:
    def test_aws_key_blocked(self):
        engine = _engine(SENSITIVE_PATTERNS)
        decision = engine.evaluate_tool_call(
            "write_file",
            {"content": "aws_key = AKIAIOSFODNN7EXAMPLE"},
        )
        assert not decision.allowed
        assert decision.code == "BLOCK_SENSITIVE_DATA"
        assert "AWS Access Key" in decision.reason

    def test_github_token_blocked(self):
        engine = _engine(SENSITIVE_PATTERNS)
        token = "ghp_" + "A" * 36
        decision = engine.evaluate_tool_call(
            "run_command",
            {"command": "curl -H 'Authorization: token " + token + "'"},
        )
        assert not decision.allowed
        assert decision.code == "BLOCK_SENSITIVE_DATA"
        assert "GitHub Token" in decision.reason

    def test_email_blocked(self):
        engine = _engine(SENSITIVE_PATTERNS)
        decision = engine.evaluate_tool_call(
            "send_message",
            {"body": "Contact me at user@example.com"},
        )
        assert not decision.allowed
        assert decision.code == "BLOCK_SENSITIVE_DATA"
        assert "Email Address" in decision.reason

    def test_ssn_blocked(self):
        engine = _engine(SENSITIVE_PATTERNS)
        decision = engine.evaluate_tool_call(
            "write_file",
            {"content": "SSN: 123-45-6789"},
        )
        assert not decision.allowed
        assert decision.code == "BLOCK_SENSITIVE_DATA"
        assert "SSN" in decision.reason

    def test_generic_api_key_blocked(self):
        engine = _engine(SENSITIVE_PATTERNS)
        decision = engine.evaluate_tool_call(
            "write_file",
            {"content": "api_key = sk-live-abc123"},
        )
        assert not decision.allowed
        assert decision.code == "BLOCK_SENSITIVE_DATA"
        assert "Generic API Key" in decision.reason

    def test_clean_arguments_pass(self):
        engine = _engine(SENSITIVE_PATTERNS)
        decision = engine.evaluate_tool_call(
            "write_file",
            {"content": "Hello, world!", "path": "greeting.txt"},
        )
        assert decision.allowed

    def test_nested_values_scanned(self):
        engine = _engine(SENSITIVE_PATTERNS)
        decision = engine.evaluate_tool_call(
            "write_file",
            {"metadata": {"inner": {"deep": "key=AKIAIOSFODNN7EXAMPLE"}}},
        )
        assert not decision.allowed
        assert decision.code == "BLOCK_SENSITIVE_DATA"
        assert "AWS Access Key" in decision.reason

    def test_no_patterns_configured_backward_compatible(self):
        engine = _engine(patterns=None)
        decision = engine.evaluate_tool_call(
            "write_file",
            {"content": "AKIAIOSFODNN7EXAMPLE"},
        )
        assert decision.allowed

    def test_empty_patterns_list_no_checking(self):
        engine = _engine(patterns=[])
        decision = engine.evaluate_tool_call(
            "write_file",
            {"content": "AKIAIOSFODNN7EXAMPLE"},
        )
        assert decision.allowed

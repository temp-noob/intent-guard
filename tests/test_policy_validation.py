from __future__ import annotations

import pytest

from intent_guard.sdk.validator import validate_policy


def test_valid_policy_returns_no_errors():
    policy = {
        "version": "1.0",
        "name": "test-policy",
        "static_rules": {
            "forbidden_tools": ["rm"],
            "protected_paths": ["/etc/*"],
            "max_tokens_per_call": 4000,
        },
    }
    assert validate_policy(policy) == []


def test_empty_policy_is_valid():
    assert validate_policy({}) == []


def test_wrong_type_forbidden_tools():
    policy = {"static_rules": {"forbidden_tools": "not-a-list"}}
    errors = validate_policy(policy)
    assert any("forbidden_tools" in e for e in errors)


def test_wrong_type_max_tokens():
    policy = {"static_rules": {"max_tokens_per_call": "big"}}
    errors = validate_policy(policy)
    assert any("max_tokens_per_call" in e for e in errors)


def test_invalid_mode():
    policy = {"semantic_rules": {"mode": "banana"}}
    errors = validate_policy(policy)
    assert any("mode" in e for e in errors)


def test_unknown_top_level_key():
    policy = {"version": "1.0", "extra_stuff": True}
    errors = validate_policy(policy)
    assert any("unknown top-level key" in e for e in errors)


def test_invalid_critical_intent_threshold_above_one():
    policy = {"semantic_rules": {"critical_intent_threshold": 1.5}}
    errors = validate_policy(policy)
    assert any("critical_intent_threshold" in e for e in errors)


def test_invalid_critical_intent_threshold_below_zero():
    policy = {"semantic_rules": {"critical_intent_threshold": -0.1}}
    errors = validate_policy(policy)
    assert any("critical_intent_threshold" in e for e in errors)


def test_custom_policy_missing_tool_name():
    policy = {"custom_policies": [{"args": {"all_present": ["x"]}}]}
    errors = validate_policy(policy)
    assert any("tool_name" in e for e in errors)


def test_valid_complex_policy():
    policy = {
        "version": "2.0",
        "name": "full-policy",
        "static_rules": {
            "forbidden_tools": ["delete_database", "purge_all"],
            "protected_paths": ["/etc/*", ".env"],
            "max_tokens_per_call": 4000,
            "injection_patterns": ["DROP TABLE"],
            "sensitive_data_patterns": [
                {"name": "api_key", "pattern": r"sk-[a-zA-Z0-9]+"},
            ],
        },
        "custom_policies": [
            {
                "tool_name": "execute_sql",
                "args": {
                    "all_present": ["query"],
                    "should_not_present": ["raw"],
                },
            },
        ],
        "semantic_rules": {
            "provider": "ollama",
            "mode": "enforce",
            "prompt_version": "v1",
            "critical_intent_threshold": 0.85,
            "constraints": [
                {"intent": "modify_source_code", "allowed_scope": "UI only"},
            ],
        },
    }
    assert validate_policy(policy) == []


def test_invalid_prompt_version():
    policy = {"semantic_rules": {"prompt_version": ""}}
    errors = validate_policy(policy)
    assert any("prompt_version" in e for e in errors)


def test_invalid_response_rules_action():
    policy = {"response_rules": {"action": "quarantine"}}
    errors = validate_policy(policy)
    assert any("response_rules.action" in e for e in errors)


def test_valid_response_rules():
    policy = {
        "response_rules": {
            "action": "redact",
            "detect_base64": True,
            "patterns": [{"name": "token", "pattern": r"ghp_[A-Za-z0-9_]+"}],
        }
    }
    errors = validate_policy(policy)
    assert errors == []

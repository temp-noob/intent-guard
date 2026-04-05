from __future__ import annotations

import copy
from typing import Any
from unittest.mock import MagicMock

import pytest

from intent_guard.sdk.log_redactor import LogRedactor
from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS = [
    {"name": "GitHub Token", "pattern": "gh[ps]_[A-Za-z0-9_]{36,}"},
    {"name": "AWS Access Key", "pattern": "AKIA[0-9A-Z]{16}"},
]

FAKE_GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def redactor() -> LogRedactor:
    return LogRedactor(SENSITIVE_PATTERNS)


# ---------------------------------------------------------------------------
# Unit tests – LogRedactor
# ---------------------------------------------------------------------------


class TestLogRedactorBasic:
    def test_github_token_redacted(self, redactor: LogRedactor) -> None:
        data = {"arguments": {"token": FAKE_GH_TOKEN}}
        result = redactor.redact(data)
        assert FAKE_GH_TOKEN not in str(result)
        assert "[REDACTED:GitHub Token]" in result["arguments"]["token"]

    def test_aws_key_redacted(self, redactor: LogRedactor) -> None:
        data = {"key": FAKE_AWS_KEY}
        result = redactor.redact(data)
        assert FAKE_AWS_KEY not in str(result)
        assert "[REDACTED:AWS Access Key]" in result["key"]

    def test_nested_dict_redacted(self, redactor: LogRedactor) -> None:
        data = {
            "outer": {
                "inner": {
                    "secret": f"prefix {FAKE_GH_TOKEN} suffix",
                }
            }
        }
        result = redactor.redact(data)
        assert FAKE_GH_TOKEN not in str(result)
        assert "[REDACTED:GitHub Token]" in result["outer"]["inner"]["secret"]

    def test_list_values_redacted(self, redactor: LogRedactor) -> None:
        data = {"tokens": [FAKE_GH_TOKEN, "safe-value", FAKE_AWS_KEY]}
        result = redactor.redact(data)
        assert FAKE_GH_TOKEN not in str(result)
        assert FAKE_AWS_KEY not in str(result)
        assert result["tokens"][1] == "safe-value"

    def test_non_matching_values_preserved(self, redactor: LogRedactor) -> None:
        data = {
            "tool": "read_file",
            "path": "/tmp/hello.txt",
            "count": 42,
            "flag": True,
            "empty": None,
        }
        result = redactor.redact(data)
        assert result == data

    def test_original_dict_not_mutated(self, redactor: LogRedactor) -> None:
        data = {"arguments": {"token": FAKE_GH_TOKEN}}
        original = copy.deepcopy(data)
        redactor.redact(data)
        assert data == original

    def test_empty_patterns_passthrough(self) -> None:
        redactor = LogRedactor([])
        data = {"token": FAKE_GH_TOKEN}
        assert redactor.redact(data) == data

    def test_invalid_pattern_skipped(self) -> None:
        patterns = [
            {"name": "Bad", "pattern": "[invalid"},
            {"name": "GitHub Token", "pattern": "gh[ps]_[A-Za-z0-9_]{36,}"},
        ]
        redactor = LogRedactor(patterns)
        data = {"token": FAKE_GH_TOKEN}
        result = redactor.redact(data)
        assert "[REDACTED:GitHub Token]" in result["token"]


# ---------------------------------------------------------------------------
# Integration test – MCPProxy logger receives redacted entries
# ---------------------------------------------------------------------------


class TestMCPProxyLogRedaction:
    def _build_proxy(self, logger: Any, redact_logs: bool = True) -> MCPProxy:
        policy = {
            "name": "test-policy",
            "version": "1.0",
            "static_rules": {
                "sensitive_data_patterns": SENSITIVE_PATTERNS,
                "redact_logs": redact_logs,
            },
        }
        engine = IntentGuardEngine(policy=policy, provider=None)
        return MCPProxy(
            engine=engine,
            target_command=["echo"],
            logger=logger,
        )

    def test_logged_entry_has_redacted_args(self) -> None:
        logged: list[dict[str, Any]] = []
        proxy = self._build_proxy(logger=logged.append)

        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {"cmd": f"curl -H 'Authorization: {FAKE_GH_TOKEN}'"},
            },
        }
        proxy.process_client_message(message)

        assert len(logged) == 1
        entry = logged[0]
        assert FAKE_GH_TOKEN not in str(entry)
        assert "[REDACTED:GitHub Token]" in str(entry)

    def test_redact_logs_false_preserves_raw(self) -> None:
        logged: list[dict[str, Any]] = []
        proxy = self._build_proxy(logger=logged.append, redact_logs=False)

        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {"cmd": f"curl -H 'Authorization: {FAKE_GH_TOKEN}'"},
            },
        }
        proxy.process_client_message(message)

        assert len(logged) == 1
        assert FAKE_GH_TOKEN in str(logged[0])

    def test_decision_object_not_mutated(self) -> None:
        """The actual decision used for enforcement must keep raw arguments."""
        logged: list[dict[str, Any]] = []
        proxy = self._build_proxy(logger=logged.append)

        arguments = {"cmd": f"curl -H 'Authorization: {FAKE_GH_TOKEN}'"}
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "run_command", "arguments": arguments},
        }
        proxy.process_client_message(message)

        # The original arguments dict passed into the message must be untouched
        assert FAKE_GH_TOKEN in arguments["cmd"]

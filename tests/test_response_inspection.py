from __future__ import annotations

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy


def _policy(action: str = "block"):
    return {
        "version": "1.0",
        "response_rules": {
            "action": action,
            "detect_base64": True,
            "patterns": [
                {"name": "GitHub Token", "pattern": r"gh[ps]_[A-Za-z0-9_]{36,}"},
                {"name": "Email", "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"},
            ],
        },
    }


def test_response_inspection_blocks_sensitive_response():
    proxy = MCPProxy(engine=IntentGuardEngine(policy=_policy("block")), target_command=[], logger=lambda _e: None)
    server_message = {"jsonrpc": "2.0", "id": 7, "result": {"text": "token ghp_123456789012345678901234567890123456"}}

    should_forward, transformed = proxy.process_server_message(server_message)
    assert should_forward is False
    assert transformed is not None
    assert transformed["error"]["code"] == -32002


def test_response_inspection_warn_allows_sensitive_response():
    logs: list[dict] = []
    proxy = MCPProxy(engine=IntentGuardEngine(policy=_policy("warn")), target_command=[], logger=logs.append)
    server_message = {"jsonrpc": "2.0", "id": 8, "result": {"text": "john.doe@example.com"}}

    should_forward, transformed = proxy.process_server_message(server_message)
    assert should_forward is True
    assert transformed is None
    assert any(entry.get("event") == "response_inspection" for entry in logs)


def test_response_inspection_redacts_sensitive_response():
    proxy = MCPProxy(engine=IntentGuardEngine(policy=_policy("redact")), target_command=[], logger=lambda _e: None)
    server_message = {
        "jsonrpc": "2.0",
        "id": 9,
        "result": {"text": "email: jane.doe@example.com token ghp_123456789012345678901234567890123456"},
    }

    should_forward, transformed = proxy.process_server_message(server_message)
    assert should_forward is True
    assert transformed is not None
    assert "[REDACTED]" in transformed["result"]["text"]


def test_response_inspection_detects_base64_encoded_secret():
    proxy = MCPProxy(engine=IntentGuardEngine(policy=_policy("block")), target_command=[], logger=lambda _e: None)
    encoded = "Z2hwXzEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Ng=="
    server_message = {"jsonrpc": "2.0", "id": 10, "result": {"blob": encoded}}

    should_forward, transformed = proxy.process_server_message(server_message)
    assert should_forward is False
    assert transformed is not None
    assert transformed["error"]["code"] == -32002

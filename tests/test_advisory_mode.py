from __future__ import annotations

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy


def _make_proxy(policy, advisory_mode=False, approval_callback=None, logger=None):
    engine = IntentGuardEngine(policy=policy)
    return MCPProxy(
        engine=engine,
        target_command=[],
        advisory_mode=advisory_mode,
        approval_callback=approval_callback,
        logger=logger,
    )


FORBIDDEN_POLICY = {
    "version": "1.0",
    "static_rules": {
        "forbidden_tools": ["delete_database"],
        "protected_paths": [".env"],
    },
}


def _tool_call_message(tool_name, arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
    }


def test_advisory_mode_forwards_forbidden_tool():
    logs = []
    proxy = _make_proxy(FORBIDDEN_POLICY, advisory_mode=True, logger=logs.append)
    should_forward, error = proxy.process_client_message(_tool_call_message("delete_database"))
    assert should_forward is True
    assert error is None


def test_advisory_mode_logs_would_block():
    logs = []
    proxy = _make_proxy(FORBIDDEN_POLICY, advisory_mode=True, logger=logs.append)
    proxy.process_client_message(_tool_call_message("delete_database"))
    assert len(logs) == 1
    assert logs[0]["would_block"] is True
    assert logs[0]["allowed"] is False


def test_advisory_mode_forwards_protected_path():
    logs = []
    proxy = _make_proxy(FORBIDDEN_POLICY, advisory_mode=True, logger=logs.append)
    should_forward, error = proxy.process_client_message(
        _tool_call_message("write_file", {"path": ".env"})
    )
    assert should_forward is True
    assert error is None
    assert logs[0]["would_block"] is True


def test_advisory_mode_skips_approval_flow():
    callback_called = False

    def fake_approval(decision, request):
        nonlocal callback_called
        callback_called = True
        return True

    policy = {
        "version": "1.0",
        "static_rules": {
            "forbidden_tools": ["dangerous_tool"],
        },
    }
    proxy = _make_proxy(policy, advisory_mode=True, approval_callback=fake_approval, logger=lambda e: None)
    should_forward, error = proxy.process_client_message(_tool_call_message("dangerous_tool"))
    assert should_forward is True
    assert callback_called is False


def test_normal_mode_still_blocks():
    logs = []
    proxy = _make_proxy(FORBIDDEN_POLICY, advisory_mode=False, logger=logs.append)
    should_forward, error = proxy.process_client_message(_tool_call_message("delete_database"))
    assert should_forward is False
    assert error is not None
    assert error["error"]["code"] == -32001


def test_advisory_mode_allowed_calls_have_would_block_false():
    logs = []
    proxy = _make_proxy(FORBIDDEN_POLICY, advisory_mode=True, logger=logs.append)
    should_forward, error = proxy.process_client_message(_tool_call_message("read_file", {"path": "README.md"}))
    assert should_forward is True
    assert error is None
    assert logs[0]["would_block"] is False
    assert logs[0]["allowed"] is True

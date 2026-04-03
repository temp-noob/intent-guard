from __future__ import annotations

from pathlib import Path

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy
from intent_guard.sdk.tool_snapshot import ToolSnapshotStore


def _tools_response(description: str):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {
                    "name": "read_file",
                    "description": description,
                    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                }
            ]
        },
    }


def test_tool_snapshot_store_detects_changes(tmp_path: Path):
    store = ToolSnapshotStore(root_dir=tmp_path / "snapshots")
    first_ok, first_reason = store.check_or_store("server-a", _tools_response("read docs"))
    second_ok, second_reason = store.check_or_store("server-a", _tools_response("read docs"))
    third_ok, third_reason = store.check_or_store("server-a", _tools_response("read docs + network exfil"))

    assert first_ok is True
    assert "created" in first_reason
    assert second_ok is True
    assert "unchanged" in second_reason
    assert third_ok is False
    assert "changed" in third_reason


def test_proxy_warn_mode_allows_tools_list_change(tmp_path: Path):
    policy = {"tool_change_rules": {"enabled": True, "action": "warn"}}
    logs: list[dict] = []
    proxy = MCPProxy(engine=IntentGuardEngine(policy=policy), target_command=["dummy"], logger=logs.append)
    proxy.tool_snapshot_store = ToolSnapshotStore(root_dir=tmp_path / "snapshots")

    first = proxy.process_server_message(_tools_response("safe"))
    second = proxy.process_server_message(_tools_response("unsafe drift"))
    assert first[0] is True
    assert second[0] is True
    assert any("TOOL_SNAPSHOT_CHANGED" == entry.get("decision_code") for entry in logs)


def test_proxy_block_mode_blocks_tools_list_change(tmp_path: Path):
    policy = {"tool_change_rules": {"enabled": True, "action": "block"}}
    proxy = MCPProxy(engine=IntentGuardEngine(policy=policy), target_command=["dummy"], logger=lambda _e: None)
    proxy.tool_snapshot_store = ToolSnapshotStore(root_dir=tmp_path / "snapshots")

    first_forward, _ = proxy.process_server_message(_tools_response("safe"))
    second_forward, second_payload = proxy.process_server_message(_tools_response("unsafe drift"))
    assert first_forward is True
    assert second_forward is False
    assert second_payload is not None
    assert second_payload["error"]["code"] == -32002

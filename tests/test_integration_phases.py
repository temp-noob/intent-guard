from __future__ import annotations

from pathlib import Path

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy
from intent_guard.sdk.providers import OllamaProvider


def test_phase1_cli_interceptor_forwards_and_logs_tool_calls():
    logs: list[dict] = []
    engine = IntentGuardEngine(policy={})
    proxy = MCPProxy(engine=engine, target_command=[], logger=logs.append)

    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "README.md"}},
    }

    should_forward, error = proxy.process_client_message(message)
    assert should_forward is True
    assert error is None
    assert logs[0]["tool"] == "read_file"
    assert logs[0]["allowed"] is True


def test_phase2_static_engine_blocks_forbidden_tool_and_protected_path(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: "1.0"
static_rules:
  forbidden_tools: ["delete_database"]
  protected_paths: [".env"]
  max_tokens_per_call: 100
""",
        encoding="utf-8",
    )

    engine = IntentGuardEngine.from_policy_file(policy_path)
    forbidden = engine.evaluate_tool_call("delete_database", {})
    protected = engine.evaluate_tool_call("write_file", {"path": ".env"})
    too_many_tokens = engine.evaluate_tool_call("generate", {"max_tokens": 101})

    assert forbidden.allowed is False
    assert protected.allowed is False
    assert too_many_tokens.allowed is False


def test_phase3_ollama_semantic_judging(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"response": "UNSAFE\nscore: 0.91"}

    def fake_post(url, json, timeout):  # noqa: A002
        assert url.endswith("/api/generate")
        assert "Task:" in json["prompt"]
        return FakeResponse()

    monkeypatch.setattr("requests.post", fake_post)
    provider = OllamaProvider(model="llama-guard3")
    engine = IntentGuardEngine(
        policy={
            "semantic_rules": {
                "critical_intent_threshold": 0.85,
                "constraints": [{"intent": "modify_source_code", "allowed_scope": "ui only"}],
            }
        },
        provider=provider,
    )

    decision = engine.evaluate_tool_call(
        "edit_file",
        {"path": "src/auth/handler.py"},
        task_context="Only update button color",
    )
    assert decision.allowed is False
    assert decision.requires_approval is True


def test_phase4_feedback_loop_pause_and_resume():
    policy = {"static_rules": {"protected_paths": [".env"]}}
    engine = IntentGuardEngine(policy=policy)
    asked: list[str] = []

    def approve(decision, _request):
        asked.append(decision.reason)
        return True

    proxy_allow = MCPProxy(engine=engine, target_command=[], approval_callback=approve)
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": ".env", "content": "X=1"}},
    }
    should_forward, error = proxy_allow.process_client_message(message)
    assert should_forward is True
    assert error is None
    assert asked

    proxy_deny = MCPProxy(engine=engine, target_command=[], approval_callback=lambda *_: False)
    should_forward, error = proxy_deny.process_client_message(message)
    assert should_forward is False
    assert error is not None
    assert "IntentGuard blocked tool call" in error["error"]["message"]

from __future__ import annotations

import base64
import json
from hashlib import sha256
from hmac import new as hmac_new
from pathlib import Path

import requests

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy, webhook_approval_callback
from intent_guard.sdk.providers import OllamaProvider


def test_phase1_cli_interceptor_forwards_and_logs_tool_calls():
    logs: list[dict] = []
    engine = IntentGuardEngine(policy={"name": "integration-policy", "version": "1.0"})
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
    assert logs[0]["decision_id"]
    assert logs[0]["decision_code"] == "ALLOW_POLICY"
    assert logs[0]["policy_name"] == "integration-policy"
    assert logs[0]["policy_version"] == "1.0"
    assert logs[0]["timestamp"].endswith("Z")


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
    assert forbidden.code == "BLOCK_FORBIDDEN_TOOL"
    assert forbidden.severity == "high"
    assert forbidden.rule_id == "static.forbidden_tools"
    assert forbidden.decision_id
    assert forbidden.timestamp.endswith("Z")
    assert protected.allowed is False
    assert too_many_tokens.allowed is False


def test_phase2_static_engine_applies_custom_policies(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: "1.0"
custom_policies:
  tool_name: tool_x
  args:
    all_present: ["path", "content", "mode"]
    should_not_present: ["sudo", "force", "recursive"]
""",
        encoding="utf-8",
    )

    engine = IntentGuardEngine.from_policy_file(policy_path)

    missing_required = engine.evaluate_tool_call("tool_x", {"path": "README.md", "content": "x"})
    has_forbidden = engine.evaluate_tool_call(
        "tool_x", {"path": "README.md", "content": "x", "mode": "write", "sudo": True}
    )
    passes = engine.evaluate_tool_call("tool_x", {"path": "README.md", "content": "x", "mode": "write"})
    other_tool = engine.evaluate_tool_call("tool_y", {"sudo": True})

    assert missing_required.allowed is False
    assert missing_required.code == "BLOCK_CUSTOM_POLICY_MISSING_ARGS"
    assert missing_required.rule_id == "custom_policies.1.args.all_present"

    assert has_forbidden.allowed is False
    assert has_forbidden.code == "BLOCK_CUSTOM_POLICY_FORBIDDEN_ARGS"
    assert has_forbidden.rule_id == "custom_policies.1.args.should_not_present"

    assert passes.allowed is True
    assert other_tool.allowed is True


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
        return {"who": "alice", "why": "manual security approval", "ttl": "2026-03-06T00:00:00Z"}

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
    assert error["error"]["data"]["decision_code"] == "BLOCK_PROTECTED_PATH"


def test_phase4_approval_override_fields_are_recorded():
    logs: list[dict] = []
    policy = {"name": "approval-policy", "version": "2.0", "static_rules": {"protected_paths": [".env"]}}
    engine = IntentGuardEngine(policy=policy)
    proxy = MCPProxy(
        engine=engine,
        target_command=[],
        logger=logs.append,
        approval_callback=lambda *_: {"who": "ops-user", "why": "break-glass", "ttl": "2026-03-06T12:00:00Z"},
    )

    message = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": ".env", "content": "X=2"}},
    }
    should_forward, error = proxy.process_client_message(message)

    assert should_forward is True
    assert error is None
    assert logs[0]["decision_code"] == "ALLOW_OVERRIDE"
    assert logs[0]["override"] == {
        "who": "ops-user",
        "why": "break-glass",
        "ttl": "2026-03-06T12:00:00Z",
    }


def test_phase4_webhook_approval_timeout_uses_default_action_allow(monkeypatch):
    policy = {"static_rules": {"protected_paths": [".env"]}}
    engine = IntentGuardEngine(policy=policy)

    def fake_post(*_args, **_kwargs):
        raise requests.Timeout("simulated timeout")

    monkeypatch.setattr("requests.post", fake_post)
    callback = webhook_approval_callback(
        webhook_url="https://approval.internal/approve",
        timeout_seconds=0.01,
        default_action="allow",
    )
    proxy = MCPProxy(engine=engine, target_command=[], approval_callback=callback)
    message = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": ".env", "content": "X=3"}},
    }

    should_forward, error = proxy.process_client_message(message)
    assert should_forward is True
    assert error is None


def test_phase4_break_glass_env_allows_without_prompt(monkeypatch):
    policy = {"static_rules": {"protected_paths": [".env"]}}
    engine = IntentGuardEngine(policy=policy)
    prompted = False

    def should_not_run(*_args, **_kwargs):
        nonlocal prompted
        prompted = True
        return False

    monkeypatch.setenv("INTENT_GUARD_BREAK_GLASS_TOKEN", "enabled")
    proxy = MCPProxy(engine=engine, target_command=[], approval_callback=should_not_run)
    message = {
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": ".env", "content": "X=4"}},
    }

    should_forward, error = proxy.process_client_message(message)
    assert should_forward is True
    assert error is None
    assert prompted is False


def test_phase4_break_glass_signed_token_validates_signature_and_expiry(monkeypatch):
    policy = {"static_rules": {"protected_paths": [".env"]}}
    engine = IntentGuardEngine(policy=policy)
    signing_key = "test-signing-key"
    payload_raw = json.dumps({"exp": 4_102_444_800}).encode("utf-8")
    payload_part = base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature_part = base64.urlsafe_b64encode(
        hmac_new(signing_key.encode("utf-8"), payload_part.encode("utf-8"), sha256).digest()
    ).decode("utf-8").rstrip("=")
    token = f"{payload_part}.{signature_part}"

    monkeypatch.setenv("INTENT_GUARD_BREAK_GLASS_SIGNED_TOKEN", token)
    monkeypatch.setenv("INTENT_GUARD_BREAK_GLASS_SIGNING_KEY", signing_key)
    proxy = MCPProxy(engine=engine, target_command=[], approval_callback=lambda *_: False)
    message = {
        "jsonrpc": "2.0",
        "id": 14,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": ".env", "content": "X=5"}},
    }

    should_forward, error = proxy.process_client_message(message)
    assert should_forward is True
    assert error is None

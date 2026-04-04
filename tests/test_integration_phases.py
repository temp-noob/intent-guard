from __future__ import annotations

import base64
import json
from hashlib import sha256
from hmac import new as hmac_new
from pathlib import Path

import pytest
import requests

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy, webhook_approval_callback
from intent_guard.sdk.providers import LiteLLMProvider, OllamaProvider, SemanticProviderUnavailable, SemanticVerdict


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
            return {"response": '{"safe": false, "score": 0.91, "reason": "violates task scope"}'}

    def fake_post(url, json, timeout):  # noqa: A002
        assert url.endswith("/api/generate")
        assert "Task:" in json["prompt"]
        assert json["format"] == "json"
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
    assert decision.semantic_prompt_version == "v1"


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


def test_semantic_mode_advisory_allows_but_records_alert():
    class FakeProvider:
        def judge(self, _prompt):
            return SemanticVerdict(safe=False, score=0.1, raw='{"safe":false,"score":0.1}', reason="context mismatch")

    engine = IntentGuardEngine(
        policy={"semantic_rules": {"mode": "advisory", "critical_intent_threshold": 0.85, "constraints": []}},
        provider=FakeProvider(),
    )

    decision = engine.evaluate_tool_call("edit_file", {"path": "src/auth/handler.py"}, task_context="touch auth")
    assert decision.allowed is True
    assert decision.code == "ALLOW_SEMANTIC_ADVISORY"
    assert decision.severity == "warning"
    assert decision.reason == "context mismatch"
    assert decision.semantic_prompt_version == "v1"


def test_semantic_provider_fail_mode_can_be_per_tool():
    class FailingProvider:
        def judge(self, _prompt):
            raise SemanticProviderUnavailable("simulated outage")

    engine = IntentGuardEngine(
        policy={
            "semantic_rules": {
                "mode": "enforce",
                "provider_fail_mode": {"default": "advisory", "by_tool": {"delete_database": "enforce"}},
                "constraints": [],
            }
        },
        provider=FailingProvider(),
    )

    critical = engine.evaluate_tool_call("delete_database", {}, task_context="maintenance")
    non_critical = engine.evaluate_tool_call("read_docs", {}, task_context="maintenance")

    assert critical.allowed is False
    assert critical.code == "BLOCK_SEMANTIC_PROVIDER_FAILURE"
    assert non_critical.allowed is True
    assert non_critical.code == "ALLOW_SEMANTIC_PROVIDER_FAILURE"


def test_ollama_provider_circuit_breaker_short_circuits_after_threshold(monkeypatch):
    calls = {"count": 0}

    def fail_post(*_args, **_kwargs):
        calls["count"] += 1
        raise requests.Timeout("simulated timeout")

    monkeypatch.setattr("requests.post", fail_post)
    monkeypatch.setattr("intent_guard.sdk.providers.time.sleep", lambda *_args, **_kwargs: None)
    provider = OllamaProvider(
        model="llama-guard3",
        retry_attempts=0,
        circuit_breaker_failures=1,
        circuit_breaker_reset_seconds=60,
    )

    with pytest.raises(SemanticProviderUnavailable):
        provider.judge("first call")
    with pytest.raises(SemanticProviderUnavailable):
        provider.judge("second call")

    assert calls["count"] == 1


def test_litellm_provider_uses_retries_and_env_model(monkeypatch):
    attempts = {"count": 0}

    def fake_completion(**kwargs):
        attempts["count"] += 1
        assert kwargs["model"] == "claude-3-5-sonnet-20241022"
        assert kwargs["response_format"] == {"type": "json_object"}
        if attempts["count"] == 1:
            raise RuntimeError("transient error")
        return {"choices": [{"message": {"content": '{"safe": true, "score": 0.92, "reason": "aligned"}'}}]}

    monkeypatch.setenv("LLM_MODEL", "claude-3-5-sonnet-20241022")
    monkeypatch.setattr("intent_guard.sdk.providers.litellm_completion", fake_completion)
    monkeypatch.setattr("intent_guard.sdk.providers.time.sleep", lambda *_args, **_kwargs: None)
    provider = LiteLLMProvider(retry_attempts=1)

    verdict = provider.judge("prompt")
    assert verdict.safe is True
    assert verdict.score == 0.92
    assert attempts["count"] == 2


def test_litellm_provider_rejects_non_json_verdict(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "claude-3-5-sonnet-20241022")
    monkeypatch.setattr(
        "intent_guard.sdk.providers.litellm_completion",
        lambda **_kwargs: {"choices": [{"message": {"content": "SAFE 0.9"}}]},
    )
    monkeypatch.setattr("intent_guard.sdk.providers.time.sleep", lambda *_args, **_kwargs: None)
    provider = LiteLLMProvider(retry_attempts=0)

    with pytest.raises(SemanticProviderUnavailable):
        provider.judge("prompt")

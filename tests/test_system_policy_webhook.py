from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy, webhook_approval_callback
from intent_guard.sdk.providers import SemanticVerdict


@dataclass
class FakeProvider:
    verdict: SemanticVerdict
    prompts: list[str]

    def judge(self, prompt: str) -> SemanticVerdict:
        self.prompts.append(prompt)
        return self.verdict


class _ApprovalHandler(BaseHTTPRequestHandler):
    responses: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    lock = threading.Lock()

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw.decode("utf-8") or "{}")
        with self.lock:
            self.requests.append(body)
            response = self.responses.pop(0) if self.responses else {"approved": False}

        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


@contextmanager
def toy_webhook_server(responses: list[dict[str, Any]]) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    _ApprovalHandler.responses = list(responses)
    _ApprovalHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ApprovalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/approve", _ApprovalHandler.requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    ("policy_text", "tool_name", "arguments"),
    [
        (
            """
version: "1.0"
static_rules:
  forbidden_tools: ["delete_database"]
""",
            "delete_database",
            {},
        ),
        (
            """
version: "1.0"
static_rules:
  protected_paths: [".env", "secrets/*"]
""",
            "write_file",
            {"path": ".env", "content": "X=1"},
        ),
        (
            """
version: "1.0"
static_rules:
  max_tokens_per_call: 100
""",
            "generate",
            {"max_tokens": 500},
        ),
        (
            """
version: "1.0"
custom_policies:
  tool_name: write_file
  args:
    all_present: ["path", "content"]
""",
            "write_file",
            {"path": "README.md"},
        ),
    ],
)
def test_system_static_policy_matrix_calls_webhook_and_blocks_by_default(
    tmp_path: Path,
    policy_text: str,
    tool_name: str,
    arguments: dict[str, Any],
):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    engine = IntentGuardEngine.from_policy_file(policy_path)

    with toy_webhook_server([{"approved": False}]) as (webhook_url, received):
        callback = webhook_approval_callback(webhook_url=webhook_url, timeout_seconds=1.0, default_action="deny")
        proxy = MCPProxy(engine=engine, target_command=[], approval_callback=callback)
        message = {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }

        should_forward, error = proxy.process_client_message(message)

    assert should_forward is False
    assert error is not None
    assert "IntentGuard blocked tool call" in error["error"]["message"]
    assert len(received) == 1
    assert received[0]["request"]["params"]["name"] == tool_name
    assert received[0]["decision"]["decision_id"]


def test_system_semantic_policy_uses_provider_and_webhook_override(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: "1.0"
semantic_rules:
  critical_intent_threshold: 0.85
  constraints:
    - intent: modify_source_code
      allowed_scope: ui only
      forbidden_scope: auth/database
""",
        encoding="utf-8",
    )
    provider = FakeProvider(verdict=SemanticVerdict(safe=False, score=0.25, raw="UNSAFE"), prompts=[])
    engine = IntentGuardEngine.from_policy_file(policy_path, provider=provider)

    with toy_webhook_server(
        [{"approved": True, "override": {"who": "ops-user", "why": "incident", "ttl": "2026-12-01T00:00:00Z"}}]
    ) as (webhook_url, received):
        callback = webhook_approval_callback(webhook_url=webhook_url, timeout_seconds=1.0, default_action="deny")
        proxy = MCPProxy(engine=engine, target_command=[], approval_callback=callback, task_context="UI updates only")
        message = {
            "jsonrpc": "2.0",
            "id": 200,
            "method": "tools/call",
            "params": {"name": "edit_file", "arguments": {"path": "src/auth/handler.py", "content": "x"}},
        }

        should_forward, error = proxy.process_client_message(message)

    assert should_forward is True
    assert error is None
    assert len(provider.prompts) == 1
    assert "Task: UI updates only" in provider.prompts[0]
    assert len(received) == 1
    assert received[0]["decision"]["code"] == "BLOCK_SEMANTIC"
    assert received[0]["request"]["params"]["name"] == "edit_file"

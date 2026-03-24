"""Integration tests for MCPProxy.run_stdio() – the stdio proxy pipeline."""

from __future__ import annotations

import io
import json
import sys
import textwrap
import threading

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ECHO_SCRIPT = textwrap.dedent("""\
    import sys
    for line in sys.stdin:
        sys.stdout.write(line)
        sys.stdout.flush()
""")


def _make_policy_file(tmp_path) -> str:
    """Create a minimal YAML policy that forbids 'delete_database'."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        textwrap.dedent("""\
            version: "1.0"
            name: test-stdio
            static_rules:
              forbidden_tools:
                - delete_database
        """)
    )
    return str(policy)


def _build_proxy(policy_path: str) -> MCPProxy:
    """Build an MCPProxy that delegates to a Python echo subprocess."""
    engine = IntentGuardEngine.from_policy_file(policy_path)
    return MCPProxy(
        engine=engine,
        target_command=[sys.executable, "-c", ECHO_SCRIPT],
        logger=lambda _entry: None,
    )


def _run_proxy_with_input(proxy: MCPProxy, stdin_text: str) -> tuple[str, int]:
    """Run proxy.run_stdio() with *stdin_text* as stdin, return (stdout, rc)."""
    fake_stdout = io.StringIO()
    fake_stdin = io.StringIO(stdin_text)

    result: dict = {}

    def _target():
        old_stdin, old_stdout = sys.stdin, sys.stdout
        try:
            sys.stdin = fake_stdin
            sys.stdout = fake_stdout
            result["rc"] = proxy.run_stdio()
        finally:
            sys.stdin = old_stdin
            sys.stdout = old_stdout

    t = threading.Thread(target=_target)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "run_stdio did not finish within 10 s"
    return fake_stdout.getvalue(), result["rc"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestProxyStdioPipeline:

    def test_allowed_call_forwarded_to_child(self, tmp_path):
        """An allowed tools/call message is forwarded to the child and echoed back."""
        policy_path = _make_policy_file(tmp_path)
        proxy = _build_proxy(policy_path)

        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
        }
        stdin_text = json.dumps(message) + "\n"

        stdout_text, rc = _run_proxy_with_input(proxy, stdin_text)
        assert rc == 0

        lines = [l for l in stdout_text.strip().splitlines() if l.strip()]
        assert len(lines) >= 1
        echoed = json.loads(lines[0])
        assert echoed == message

    def test_blocked_call_returns_error_without_forwarding(self, tmp_path):
        """A blocked tool call produces a JSON-RPC error and is NOT forwarded."""
        policy_path = _make_policy_file(tmp_path)
        proxy = _build_proxy(policy_path)

        message = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "delete_database", "arguments": {}},
        }
        stdin_text = json.dumps(message) + "\n"

        stdout_text, rc = _run_proxy_with_input(proxy, stdin_text)
        assert rc == 0

        lines = [l for l in stdout_text.strip().splitlines() if l.strip()]
        assert len(lines) == 1, "Blocked call must not be echoed; only the error should appear"

        error_resp = json.loads(lines[0])
        assert error_resp["id"] == 2
        assert "error" in error_resp
        assert error_resp["error"]["code"] == -32001

    def test_non_json_lines_forwarded_verbatim(self, tmp_path):
        """Non-JSON text is forwarded to the child process unchanged."""
        policy_path = _make_policy_file(tmp_path)
        proxy = _build_proxy(policy_path)

        stdin_text = "hello world\n"

        stdout_text, rc = _run_proxy_with_input(proxy, stdin_text)
        assert rc == 0

        lines = stdout_text.strip().splitlines()
        assert any("hello world" in l for l in lines)

    def test_child_process_cleanup_on_stdin_eof(self, tmp_path):
        """When stdin reaches EOF, child.stdin is closed and child.wait() returns 0."""
        policy_path = _make_policy_file(tmp_path)
        proxy = _build_proxy(policy_path)

        stdout_text, rc = _run_proxy_with_input(proxy, "")
        assert rc == 0

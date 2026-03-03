from __future__ import annotations

import json
import shlex
import subprocess
import sys
import threading
from typing import Any, Callable

from intent_guard.sdk.engine import GuardDecision, IntentGuardEngine

ApprovalCallback = Callable[[GuardDecision, dict[str, Any]], bool]
LogCallback = Callable[[dict[str, Any]], None]


def terminal_approval_prompt(decision: GuardDecision, request: dict[str, Any]) -> bool:
    tool_name = request.get("params", {}).get("name", "unknown")
    prompt = f"IntentGuard: Agent wants to run {tool_name}. {decision.reason}. Allow? [y/N] "
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            answer = tty.readline().strip().lower()
            return answer in {"y", "yes"}
    except OSError:
        return False


class MCPProxy:
    def __init__(
        self,
        engine: IntentGuardEngine,
        target_command: list[str],
        approval_callback: ApprovalCallback | None = None,
        task_context: str | None = None,
        logger: LogCallback | None = None,
    ):
        self.engine = engine
        self.target_command = target_command
        self.approval_callback = approval_callback
        self.task_context = task_context
        self.logger = logger

    def process_client_message(self, message: dict[str, Any]) -> tuple[bool, dict[str, Any] | None]:
        if message.get("method") != "tools/call":
            return True, None

        params = message.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or params.get("args") or {}
        decision = self.engine.evaluate_tool_call(tool_name=tool_name, arguments=arguments, task_context=self.task_context)

        if not decision.allowed and self.approval_callback is not None and decision.requires_approval:
            if self.approval_callback(decision, message):
                decision = GuardDecision(allowed=True, reason="approved by user")

        self._log_tool_call(tool_name, arguments, decision)
        if decision.allowed:
            return True, None

        error = {
            "jsonrpc": message.get("jsonrpc", "2.0"),
            "id": message.get("id"),
            "error": {"code": -32001, "message": f"IntentGuard blocked tool call: {decision.reason}"},
        }
        return False, error

    def _log_tool_call(self, tool_name: str, arguments: dict[str, Any], decision: GuardDecision) -> None:
        entry = {
            "tool": tool_name,
            "arguments": arguments,
            "allowed": decision.allowed,
            "reason": decision.reason,
        }
        if self.logger is not None:
            self.logger(entry)
        else:
            sys.stderr.write(json.dumps(entry) + "\n")
            sys.stderr.flush()

    def run_stdio(self) -> int:
        child = subprocess.Popen(
            self.target_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        def forward_stream(source: Any, target: Any) -> None:
            for line in source:
                target.write(line)
                target.flush()

        stdout_thread = threading.Thread(target=forward_stream, args=(child.stdout, sys.stdout), daemon=True)
        stderr_thread = threading.Thread(target=forward_stream, args=(child.stderr, sys.stderr), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        assert child.stdin is not None
        for line in sys.stdin:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                child.stdin.write(line)
                child.stdin.flush()
                continue

            should_forward, error_response = self.process_client_message(message)
            if should_forward:
                child.stdin.write(line)
                child.stdin.flush()
            elif error_response is not None:
                sys.stdout.write(json.dumps(error_response) + "\n")
                sys.stdout.flush()

        child.stdin.close()
        return child.wait()


def parse_target_command(target: str) -> list[str]:
    return shlex.split(target)

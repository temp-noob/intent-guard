from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import threading
import time
from base64 import urlsafe_b64decode
from hashlib import sha256
from hmac import compare_digest, new as hmac_new
from typing import Any, Callable

import requests

from intent_guard.sdk.engine import GuardDecision, IntentGuardEngine
from intent_guard.sdk.response_guard import ResponseGuard

ApprovalCallback = Callable[[GuardDecision, dict[str, Any]], bool | dict[str, Any]]
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


def webhook_approval_callback(
    webhook_url: str,
    timeout_seconds: float = 10.0,
    default_action: str = "deny",
    auth_token: str | None = None,
) -> ApprovalCallback:
    default_allow = default_action.lower() == "allow"

    def callback(decision: GuardDecision, request: dict[str, Any]) -> bool | dict[str, Any]:
        payload = {
            "decision": {
                "decision_id": decision.decision_id,
                "reason": decision.reason,
                "code": decision.code,
                "severity": decision.severity,
                "policy_name": decision.policy_name,
                "policy_version": decision.policy_version,
                "rule_id": decision.rule_id,
                "timestamp": decision.timestamp,
                "semantic_prompt_version": decision.semantic_prompt_version,
            },
            "request": {
                "id": request.get("id"),
                "method": request.get("method"),
                "params": request.get("params", {}),
            },
        }
        headers = {"Content-Type": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        try:
            response = requests.post(webhook_url, json=payload, headers=headers, timeout=timeout_seconds)
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError):
            return default_allow

        approved = body.get("approved")
        if approved is None:
            return default_allow
        if not approved:
            return False
        override = body.get("override")
        return override if isinstance(override, dict) else True

    return callback


def _decode_urlsafe_b64(value: str) -> bytes:
    padding_length = (-len(value)) % 4
    padding = "=" * padding_length
    return urlsafe_b64decode(value + padding)


class MCPProxy:
    def __init__(
        self,
        engine: IntentGuardEngine,
        target_command: list[str],
        approval_callback: ApprovalCallback | None = None,
        task_context: str | None = None,
        logger: LogCallback | None = None,
        advisory_mode: bool = False,
    ):
        self.engine = engine
        self.target_command = target_command
        self.approval_callback = approval_callback
        self.task_context = task_context
        self.logger = logger
        self.advisory_mode = advisory_mode
        self.response_guard = ResponseGuard(self.engine.policy.get("response_rules", {}))

    def process_client_message(self, message: dict[str, Any]) -> tuple[bool, dict[str, Any] | None]:
        if message.get("method") != "tools/call":
            return True, None

        params = message.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or params.get("args") or {}
        decision = self.engine.evaluate_tool_call(tool_name=tool_name, arguments=arguments, task_context=self.task_context)

        if not self.advisory_mode and not decision.allowed and decision.requires_approval:
            if self._has_break_glass_override():
                decision = self.engine.build_override_decision(
                    override={"who": "ci-break-glass", "why": "break-glass token accepted", "ttl": None}
                )
            elif self.approval_callback is not None:
                approval_result = self.approval_callback(decision, message)
                if approval_result:
                    override = approval_result if isinstance(approval_result, dict) else None
                    decision = self.engine.build_override_decision(override=override)

        self._log_tool_call(tool_name, arguments, decision)

        if self.advisory_mode:
            return True, None

        if decision.allowed:
            return True, None

        error = {
            "jsonrpc": message.get("jsonrpc", "2.0"),
            "id": message.get("id"),
            "error": {
                "code": -32001,
                "message": f"IntentGuard blocked tool call: {decision.reason}",
                "data": {
                    "decision_id": decision.decision_id,
                    "decision_code": decision.code,
                    "severity": decision.severity,
                    "policy_name": decision.policy_name,
                    "policy_version": decision.policy_version,
                    "rule_id": decision.rule_id,
                    "timestamp": decision.timestamp,
                    "semantic_prompt_version": decision.semantic_prompt_version,
                },
            },
        }
        return False, error

    def process_server_message(self, message: dict[str, Any]) -> tuple[bool, dict[str, Any] | None]:
        decision = self.response_guard.inspect(message)
        self._log_response_decision(decision)

        if decision.allow and decision.redacted_response is not None:
            return True, decision.redacted_response
        if decision.allow:
            return True, None
        return False, self._response_block_error(message, decision.reason)

    def _log_tool_call(self, tool_name: str, arguments: dict[str, Any], decision: GuardDecision) -> None:
        entry = {
            "tool": tool_name,
            "arguments": arguments,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "decision_id": decision.decision_id,
            "decision_code": decision.code,
            "severity": decision.severity,
            "policy_name": decision.policy_name,
            "policy_version": decision.policy_version,
            "rule_id": decision.rule_id,
            "timestamp": decision.timestamp,
            "override": decision.override,
            "semantic_prompt_version": decision.semantic_prompt_version,
            "would_block": not decision.allowed,
        }
        if self.logger is not None:
            self.logger(entry)
        else:
            sys.stderr.write(json.dumps(entry) + "\n")
            sys.stderr.flush()

    def _log_response_decision(self, decision: Any) -> None:
        entry = {
            "event": "response_inspection",
            "allowed": decision.allow,
            "reason": decision.reason,
            "decision_code": decision.code,
            "severity": decision.severity,
        }
        if self.logger is not None:
            self.logger(entry)
        else:
            sys.stderr.write(json.dumps(entry) + "\n")
            sys.stderr.flush()

    @staticmethod
    def _response_block_error(message: dict[str, Any], reason: str) -> dict[str, Any]:
        return {
            "jsonrpc": message.get("jsonrpc", "2.0"),
            "id": message.get("id"),
            "error": {
                "code": -32002,
                "message": f"IntentGuard blocked MCP response: {reason}",
                "data": {"decision_code": "BLOCK_RESPONSE", "severity": "high"},
            },
        }

    def run_stdio(self) -> int:
        child = subprocess.Popen(
            self.target_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        def forward_stdout_stream(source: Any, target: Any) -> None:
            for line in source:
                stripped = line.strip()
                if not stripped:
                    target.write(line)
                    target.flush()
                    continue
                try:
                    message = json.loads(stripped)
                except json.JSONDecodeError:
                    target.write(line)
                    target.flush()
                    continue

                should_forward, transformed = self.process_server_message(message)
                if not should_forward:
                    if transformed is not None:
                        target.write(json.dumps(transformed) + "\n")
                        target.flush()
                    continue
                if transformed is not None:
                    target.write(json.dumps(transformed) + "\n")
                    target.flush()
                    continue
                target.write(line)
                target.flush()

        def forward_stream(source: Any, target: Any) -> None:
            for line in source:
                target.write(line)
                target.flush()

        stdout_thread = threading.Thread(target=forward_stdout_stream, args=(child.stdout, sys.stdout), daemon=True)
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

    @staticmethod
    def _has_break_glass_override() -> bool:
        break_glass_token = os.environ.get("INTENT_GUARD_BREAK_GLASS_TOKEN")
        if break_glass_token:
            return True

        signed_token = os.environ.get("INTENT_GUARD_BREAK_GLASS_SIGNED_TOKEN")
        signing_key = os.environ.get("INTENT_GUARD_BREAK_GLASS_SIGNING_KEY")
        if not signed_token or not signing_key:
            return False
        return MCPProxy._verify_signed_break_glass_token(signed_token, signing_key)

    @staticmethod
    def _verify_signed_break_glass_token(token: str, signing_key: str) -> bool:
        try:
            payload_part, signature_part = token.split(".", 1)
            expected_signature = hmac_new(signing_key.encode("utf-8"), payload_part.encode("utf-8"), sha256).digest()
            if not compare_digest(_decode_urlsafe_b64(signature_part), expected_signature):
                return False
            payload = json.loads(_decode_urlsafe_b64(payload_part).decode("utf-8"))
            exp = int(payload.get("exp", 0))
            return exp >= int(time.time())
        except (ValueError, json.JSONDecodeError, TypeError):
            return False


def parse_target_command(target: str) -> list[str]:
    return shlex.split(target)

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_evaluate(policy_text: str, payload: dict, extra_args: list[str] | None = None):
    policy_path = REPO_ROOT / ".tmp-hook-policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    try:
        command = [
            sys.executable,
            "-m",
            "intent_guard.cli",
            "evaluate",
            "--policy",
            str(policy_path),
        ]
        if extra_args:
            command.extend(extra_args)

        completed = subprocess.run(
            command,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        return completed
    finally:
        if policy_path.exists():
            policy_path.unlink()


def test_evaluate_blocks_forbidden_tool_from_generic_payload():
    completed = _run_evaluate(
        policy_text="""
version: "1.0"
static_rules:
  forbidden_tools: ["delete_database"]
""",
        payload={"tool_name": "delete_database", "arguments": {}},
    )
    assert completed.returncode == 1
    body = json.loads(completed.stdout.strip())
    assert body["allowed"] is False
    assert body["code"] == "BLOCK_FORBIDDEN_TOOL"


def test_evaluate_allows_safe_tool_from_claude_style_payload():
    completed = _run_evaluate(
        policy_text="""
version: "1.0"
static_rules:
  forbidden_tools: ["delete_database"]
""",
        payload={
            "tool_name": "read_file",
            "tool_input": {"path": "README.md"},
            "prompt": "read documentation",
        },
    )
    assert completed.returncode == 0
    body = json.loads(completed.stdout.strip())
    assert body["allowed"] is True
    assert body["tool_name"] == "read_file"
    assert body["arguments"]["path"] == "README.md"


def test_evaluate_supports_copilot_style_payload_nested_params():
    completed = _run_evaluate(
        policy_text="""
version: "1.0"
static_rules:
  protected_paths: [".env"]
""",
        payload={
            "params": {
                "name": "write_file",
                "arguments": {"path": ".env", "content": "x"},
            }
        },
    )
    assert completed.returncode == 1
    body = json.loads(completed.stdout.strip())
    assert body["allowed"] is False
    assert body["code"] == "BLOCK_PROTECTED_PATH"


def test_evaluate_accepts_tool_and_args_overrides():
    completed = _run_evaluate(
        policy_text="""
version: "1.0"
static_rules:
  forbidden_tools: ["delete_database"]
""",
        payload={},
        extra_args=["--tool", "delete_database", "--args", "{}"],
    )
    assert completed.returncode == 1
    body = json.loads(completed.stdout.strip())
    assert body["tool_name"] == "delete_database"


def test_evaluate_returns_code_2_for_invalid_stdin_json():
    policy_path = REPO_ROOT / ".tmp-hook-policy.yaml"
    policy_path.write_text('version: "1.0"\n', encoding="utf-8")
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "intent_guard.cli",
                "evaluate",
                "--policy",
                str(policy_path),
            ],
            input="{invalid",
            text=True,
            capture_output=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
    finally:
        if policy_path.exists():
            policy_path.unlink()

    assert completed.returncode == 2
    body = json.loads(completed.stdout.strip())
    assert "error" in body


def test_hook_templates_exist():
    assert (REPO_ROOT / "hooks" / "claude-code" / "settings.json").exists()
    assert (REPO_ROOT / "hooks" / "copilot" / "hooks.json").exists()
    assert (REPO_ROOT / "hooks" / "cursor" / "hooks.json").exists()

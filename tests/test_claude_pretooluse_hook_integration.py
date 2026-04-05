from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.cc_ig_integration
REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_pretooluse_hook_command(
    hook_command: str, payload: dict, cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", "-c", hook_command],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=str(cwd),
        env=env,
        check=False,
    )


def test_claude_pretooluse_hook_runs_intent_guard_evaluate(tmp_path: Path):
    if shutil.which("claude") is None and shutil.which("claude-code") is None:
        pytest.skip("requires claude-code installation")

    shim_path = tmp_path / "intent-guard"
    shim_path.write_text(
        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -m intent_guard.cli \"$@\"\n",
        encoding="utf-8",
    )
    shim_path.chmod(0o755)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: "1.0"
static_rules:
  forbidden_tools: ["delete_database"]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    settings = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"cat | intent-guard evaluate --policy {shlex.quote(str(policy_path))}",
                        }
                    ],
                }
            ]
        }
    }
    settings_dir = tmp_path / ".claude"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "settings.json"
    settings_path.write_text(json.dumps(settings), encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = f"{tmp_path}{os.pathsep}{env.get('PATH', '')}"
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{REPO_ROOT}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else str(REPO_ROOT)
    )

    loaded_settings = json.loads(settings_path.read_text(encoding="utf-8"))
    command = loaded_settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert command.startswith("cat | intent-guard evaluate --policy ")

    blocked_payload = {
        "event": "PreToolUse",
        "session_id": "sess-123",
        "tool_name": "delete_database",
        "arguments": {"database": "customer-prod"},
        "prompt": "Clean up old data",
    }
    blocked = _run_pretooluse_hook_command(command, blocked_payload, cwd=tmp_path, env=env)
    assert blocked.returncode == 1
    blocked_json = json.loads(blocked.stdout.strip())
    assert blocked_json["allowed"] is False
    assert blocked_json["code"] == "BLOCK_FORBIDDEN_TOOL"

    allowed_payload = {
        "event": "PreToolUse",
        "session_id": "sess-123",
        "tool_name": "read_file",
        "arguments": {"path": "README.md"},
        "prompt": "Read repository documentation",
    }
    allowed = _run_pretooluse_hook_command(command, allowed_payload, cwd=tmp_path, env=env)
    assert allowed.returncode == 0
    allowed_json = json.loads(allowed.stdout.strip())
    assert allowed_json["allowed"] is True
    assert allowed_json["tool_name"] == "read_file"

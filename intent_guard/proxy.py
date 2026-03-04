from __future__ import annotations

import argparse
import os
import sys

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy, parse_target_command, terminal_approval_prompt
from intent_guard.sdk.providers import OllamaProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IntentGuard MCP proxy")
    parser.add_argument("--policy", required=True, help="Path to policy YAML file")
    parser.add_argument("--target", required=True, help="Target MCP command")
    parser.add_argument("--model", default=None, help="Guardrail model override")
    parser.add_argument("--task", default=None, help="Current task context")
    parser.add_argument("--ask-approval", action="store_true", help="Prompt before allowing flagged actions")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    policy_engine = IntentGuardEngine.from_policy_file(
        args.policy,
        provider=OllamaProvider(args.model) if args.model else None,
    )
    task_context = args.task or os.environ.get("INTENT_GUARD_TASK")
    proxy = MCPProxy(
        engine=policy_engine,
        target_command=parse_target_command(args.target),
        task_context=task_context,
        approval_callback=terminal_approval_prompt if args.ask_approval else None,
    )
    return proxy.run_stdio()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

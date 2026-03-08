from __future__ import annotations

import argparse
import os
import sys

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy, parse_target_command, terminal_approval_prompt, webhook_approval_callback
from intent_guard.sdk.providers import OllamaProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IntentGuard MCP proxy")
    parser.add_argument("--policy", required=True, help="Path to policy YAML file")
    parser.add_argument("--target", required=True, help="Target MCP command")
    parser.add_argument("--model", default=None, help="Guardrail model override")
    parser.add_argument("--task", default=None, help="Current task context")
    parser.add_argument("--ask-approval", action="store_true", help="Prompt before allowing flagged actions")
    parser.add_argument("--approval-webhook", default=None, help="Webhook URL for non-interactive approval")
    parser.add_argument(
        "--approval-timeout",
        type=float,
        default=10.0,
        help="Approval webhook timeout in seconds",
    )
    parser.add_argument(
        "--approval-default-action",
        choices=["allow", "deny"],
        default="deny",
        help="Action when approval webhook times out or fails",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    policy_engine = IntentGuardEngine.from_policy_file(
        args.policy,
        provider=OllamaProvider(args.model) if args.model else None,
    )
    task_context = args.task or os.environ.get("INTENT_GUARD_TASK")
    approval_callback = None
    if args.approval_webhook:
        approval_callback = webhook_approval_callback(
            webhook_url=args.approval_webhook,
            timeout_seconds=args.approval_timeout,
            default_action=args.approval_default_action,
            auth_token=os.environ.get("INTENT_GUARD_APPROVAL_AUTH_TOKEN"),
        )
    elif args.ask_approval:
        approval_callback = terminal_approval_prompt
    proxy = MCPProxy(
        engine=policy_engine,
        target_command=parse_target_command(args.target),
        task_context=task_context,
        approval_callback=approval_callback,
    )
    return proxy.run_stdio()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

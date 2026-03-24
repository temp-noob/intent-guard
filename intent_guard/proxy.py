from __future__ import annotations

import argparse
import os
import shlex
import sys

import yaml

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy, parse_target_command, terminal_approval_prompt, webhook_approval_callback
from intent_guard.sdk.providers import LiteLLMProvider, OllamaProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IntentGuard MCP proxy")
    parser.add_argument("--policy", required=True, help="Path to policy YAML file")
    parser.add_argument("--target", default=None, help="Target MCP command")
    parser.add_argument("--validate", action="store_true", help="Validate policy file and exit")
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
    parser.add_argument("--watch-policy", action="store_true", help="Watch policy file for changes and reload")
    parser.add_argument("--advisory", action="store_true", help="Advisory mode: log violations but never block")
    return parser


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip()
            try:
                parsed = shlex.split(value, posix=True)
                if parsed:
                    value = parsed[0]
            except ValueError:
                pass
            os.environ.setdefault(key, value)


def _build_provider(args: argparse.Namespace, semantic_rules: dict) -> OllamaProvider | LiteLLMProvider | None:
    if not semantic_rules:
        return None

    retry_attempts = int(semantic_rules.get("retry_attempts", 2))
    retry_base_delay_seconds = float(semantic_rules.get("retry_base_delay_seconds", 0.25))
    retry_max_delay_seconds = float(semantic_rules.get("retry_max_delay_seconds", 2.0))
    retry_jitter_ratio = float(semantic_rules.get("retry_jitter_ratio", 0.2))
    circuit_breaker_failures = int(semantic_rules.get("circuit_breaker_failures", 3))
    circuit_breaker_reset_seconds = float(semantic_rules.get("circuit_breaker_reset_seconds", 30.0))
    provider_timeout_seconds = float(semantic_rules.get("provider_timeout_seconds", 5.0))

    provider_name = str(semantic_rules.get("provider", "")).strip().lower()
    if provider_name == "litellm" or (provider_name != "ollama" and os.environ.get("LLM_MODEL")):
        return LiteLLMProvider(
            timeout=provider_timeout_seconds,
            retry_attempts=retry_attempts,
            retry_base_delay_seconds=retry_base_delay_seconds,
            retry_max_delay_seconds=retry_max_delay_seconds,
            retry_jitter_ratio=retry_jitter_ratio,
            circuit_breaker_failures=circuit_breaker_failures,
            circuit_breaker_reset_seconds=circuit_breaker_reset_seconds,
        )

    model = args.model or semantic_rules.get("guardrail_model")
    if model:
        return OllamaProvider(
            model=model,
            timeout=provider_timeout_seconds,
            retry_attempts=retry_attempts,
            retry_base_delay_seconds=retry_base_delay_seconds,
            retry_max_delay_seconds=retry_max_delay_seconds,
            retry_jitter_ratio=retry_jitter_ratio,
            circuit_breaker_failures=circuit_breaker_failures,
            circuit_breaker_reset_seconds=circuit_breaker_reset_seconds,
        )
    return None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _load_dotenv()

    with open(args.policy, "r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle) or {}

    if args.validate:
        from intent_guard.sdk.validator import validate_policy

        errors = validate_policy(policy)
        if errors:
            for err in errors:
                sys.stderr.write(f"ERROR: {err}\n")
            return 1
        sys.stdout.write("Policy is valid.\n")
        return 0

    if not args.target:
        parser.error("--target is required when not using --validate")

    provider = _build_provider(args, policy.get("semantic_rules", {}))
    policy_engine = IntentGuardEngine(policy=policy, provider=provider)
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
        advisory_mode=args.advisory,
    )
    if args.watch_policy:
        from intent_guard.sdk.watcher import PolicyWatcher

        watcher = PolicyWatcher(
            policy_path=args.policy,
            on_reload=policy_engine.reload_policy,
        )
        watcher.start()

    return proxy.run_stdio()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

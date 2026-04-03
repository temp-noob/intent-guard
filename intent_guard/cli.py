from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

import yaml

from intent_guard.proxy import _build_provider, _load_dotenv
from intent_guard.sdk.engine import IntentGuardEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IntentGuard command line interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a tool call and return allow/block decision")
    evaluate.add_argument("--policy", required=True, help="Path to policy YAML file")
    evaluate.add_argument("--model", default=None, help="Guardrail model override")
    evaluate.add_argument("--task", default=None, help="Task context override")
    evaluate.add_argument("--tool", default=None, help="Tool name override (if stdin does not include it)")
    evaluate.add_argument(
        "--args",
        default=None,
        help="Tool arguments as JSON object string (used when stdin payload omits arguments)",
    )
    evaluate.set_defaults(handler=run_evaluate)

    return parser


def run_evaluate(args: argparse.Namespace) -> int:
    _load_dotenv()
    with open(args.policy, "r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle) or {}

    provider = _build_provider(args, policy.get("semantic_rules", {}))
    engine = IntentGuardEngine(policy=policy, provider=provider)

    payload = _read_stdin_payload()
    tool_name, arguments, task_context = _normalize_hook_input(
        payload=payload,
        tool_override=args.tool,
        args_override=args.args,
        task_override=args.task,
    )

    if not tool_name:
        _emit_json({"error": "unable to determine tool name from input payload"})
        return 2

    decision = engine.evaluate_tool_call(
        tool_name=tool_name,
        arguments=arguments,
        task_context=task_context,
    )

    output = asdict(decision)
    output["tool_name"] = tool_name
    output["arguments"] = arguments
    output["task_context"] = task_context
    _emit_json(output)
    return 0 if decision.allowed else 1


def _read_stdin_payload() -> dict[str, Any]:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("stdin must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("stdin JSON must be an object")
    return payload


def _normalize_hook_input(
    payload: dict[str, Any],
    tool_override: str | None,
    args_override: str | None,
    task_override: str | None,
) -> tuple[str, dict[str, Any], str | None]:
    tool_name = tool_override or _extract_first_str(
        payload,
        [
            "tool_name",
            "toolName",
            "name",
            "tool",
        ],
    )
    arguments_value: Any = None
    task_context = task_override or _extract_first_str(
        payload,
        ["task_context", "taskContext", "task", "prompt", "user_prompt", "userPrompt"],
    )

    nested_candidates = [
        payload.get("tool_call"),
        payload.get("toolCall"),
        payload.get("call"),
        payload.get("params"),
        payload.get("input"),
        payload.get("data"),
    ]

    for nested in nested_candidates:
        if not isinstance(nested, dict):
            continue
        if not tool_name:
            tool_name = _extract_first_str(nested, ["tool_name", "toolName", "name", "tool"])
        if arguments_value is None:
            arguments_value = _extract_first_value(
                nested,
                ["arguments", "args", "tool_input", "toolInput", "input"],
            )
        if task_context is None:
            task_context = _extract_first_str(nested, ["task_context", "taskContext", "task", "prompt"])

    if arguments_value is None:
        arguments_value = _extract_first_value(
            payload,
            ["arguments", "args", "tool_input", "toolInput", "input"],
        )

    if args_override is not None:
        parsed = json.loads(args_override)
        arguments_value = parsed

    arguments = _coerce_arguments(arguments_value)
    return (tool_name or "", arguments, task_context)


def _coerce_arguments(arguments_value: Any) -> dict[str, Any]:
    if arguments_value is None:
        return {}
    if isinstance(arguments_value, dict):
        return arguments_value
    if isinstance(arguments_value, str):
        stripped = arguments_value.strip()
        if not stripped:
            return {}
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return {"value": arguments_value}
        if isinstance(parsed, dict):
            return parsed
        return {"value": parsed}
    return {"value": arguments_value}


def _extract_first_str(payload: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _extract_first_value(payload: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in payload:
            return payload.get(key)
    return None


def _emit_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except ValueError as exc:
        _emit_json({"error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

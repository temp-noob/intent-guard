from __future__ import annotations

from typing import Any

KNOWN_TOP_LEVEL_KEYS = {
    "version",
    "name",
    "static_rules",
    "custom_policies",
    "semantic_rules",
    "response_rules",
    "tool_change_rules",
}
VALID_PROVIDERS = {"ollama", "litellm"}
VALID_MODES = {"off", "enforce", "advisory"}


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Return a list of validation error/warning strings. Empty list means valid."""
    if not isinstance(policy, dict):
        return ["policy must be a dict"]

    errors: list[str] = []

    for key in policy:
        if key not in KNOWN_TOP_LEVEL_KEYS:
            errors.append(f"unknown top-level key: \'{key}\'")

    if "version" in policy and not isinstance(policy["version"], str):
        errors.append("\'version\' must be a string")

    if "name" in policy and not isinstance(policy["name"], str):
        errors.append("\'name\' must be a string")

    if "static_rules" in policy:
        errors.extend(_validate_static_rules(policy["static_rules"]))

    if "custom_policies" in policy:
        errors.extend(_validate_custom_policies(policy["custom_policies"]))

    if "semantic_rules" in policy:
        errors.extend(_validate_semantic_rules(policy["semantic_rules"]))

    if "response_rules" in policy:
        errors.extend(_validate_response_rules(policy["response_rules"]))
    if "tool_change_rules" in policy:
        errors.extend(_validate_tool_change_rules(policy["tool_change_rules"]))

    return errors


def _validate_static_rules(rules: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(rules, dict):
        return ["\'static_rules\' must be a dict"]

    if "forbidden_tools" in rules:
        ft = rules["forbidden_tools"]
        if not isinstance(ft, list) or not all(isinstance(t, str) for t in ft):
            errors.append("\'static_rules.forbidden_tools\' must be a list of strings")

    if "protected_paths" in rules:
        pp = rules["protected_paths"]
        if not isinstance(pp, list) or not all(isinstance(p, str) for p in pp):
            errors.append("\'static_rules.protected_paths\' must be a list of strings")

    if "max_tokens_per_call" in rules:
        mt = rules["max_tokens_per_call"]
        if not isinstance(mt, int) or isinstance(mt, bool) or mt <= 0:
            errors.append("\'static_rules.max_tokens_per_call\' must be a positive integer")

    if "injection_patterns" in rules:
        ip = rules["injection_patterns"]
        if not isinstance(ip, list) or not all(isinstance(p, str) for p in ip):
            errors.append("\'static_rules.injection_patterns\' must be a list of strings")

    if "sensitive_data_patterns" in rules:
        sdp = rules["sensitive_data_patterns"]
        if not isinstance(sdp, list):
            errors.append("\'static_rules.sensitive_data_patterns\' must be a list of dicts with \'name\' and \'pattern\'")
        else:
            for i, item in enumerate(sdp):
                if not isinstance(item, dict) or "name" not in item or "pattern" not in item:
                    errors.append(
                        f"\'static_rules.sensitive_data_patterns[{i}]\' must be a dict with \'name\' and \'pattern\'"
                    )

    if "decode_arguments" in rules and not isinstance(rules["decode_arguments"], bool):
        errors.append("'static_rules.decode_arguments' must be boolean")

    return errors


def _validate_custom_policies(policies: Any) -> list[str]:
    errors: list[str] = []
    if isinstance(policies, dict):
        policies = [policies]
    elif not isinstance(policies, list):
        return ["\'custom_policies\' must be a list of dicts or a single dict"]

    for i, item in enumerate(policies):
        if not isinstance(item, dict):
            errors.append(f"\'custom_policies[{i}]\' must be a dict")
            continue
        if "tool_name" not in item:
            errors.append(f"\'custom_policies[{i}]\' missing required key \'tool_name\'")
        elif not isinstance(item["tool_name"], str):
            errors.append(f"\'custom_policies[{i}].tool_name\' must be a string")
        if "args" in item:
            args = item["args"]
            if not isinstance(args, dict):
                errors.append(f"\'custom_policies[{i}].args\' must be a dict")
            else:
                if "all_present" in args and not isinstance(args["all_present"], list):
                    errors.append(f"\'custom_policies[{i}].args.all_present\' must be a list")
                if "should_not_present" in args and not isinstance(args["should_not_present"], list):
                    errors.append(f"\'custom_policies[{i}].args.should_not_present\' must be a list")

    return errors


def _validate_semantic_rules(rules: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(rules, dict):
        return ["\'semantic_rules\' must be a dict"]

    if "provider" in rules:
        if rules["provider"] not in VALID_PROVIDERS:
            errors.append(f"\'semantic_rules.provider\' must be one of {sorted(VALID_PROVIDERS)}")

    if "mode" in rules:
        if rules["mode"] not in VALID_MODES:
            errors.append(f"\'semantic_rules.mode\' must be one of {sorted(VALID_MODES)}")

    if "critical_intent_threshold" in rules:
        cit = rules["critical_intent_threshold"]
        if not isinstance(cit, (int, float)) or isinstance(cit, bool) or not (0 <= cit <= 1):
            errors.append("\'semantic_rules.critical_intent_threshold\' must be a float between 0 and 1")

    if "prompt_version" in rules:
        pv = rules["prompt_version"]
        if not isinstance(pv, str) or not pv.strip():
            errors.append("\'semantic_rules.prompt_version\' must be a non-empty string")

    if "constraints" in rules:
        c = rules["constraints"]
        if not isinstance(c, list):
            errors.append("\'semantic_rules.constraints\' must be a list of dicts")
        else:
            for i, item in enumerate(c):
                if not isinstance(item, dict):
                    errors.append(f"\'semantic_rules.constraints[{i}]\' must be a dict")

    return errors


def _validate_response_rules(rules: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(rules, dict):
        return ["'response_rules' must be a dict"]

    if "action" in rules:
        action = rules["action"]
        if action not in {"block", "warn", "redact"}:
            errors.append("'response_rules.action' must be one of ['block', 'warn', 'redact']")

    if "detect_base64" in rules and not isinstance(rules["detect_base64"], bool):
        errors.append("'response_rules.detect_base64' must be boolean")

    if "patterns" in rules:
        patterns = rules["patterns"]
        if not isinstance(patterns, list):
            errors.append("'response_rules.patterns' must be a list")
        else:
            for i, item in enumerate(patterns):
                if not isinstance(item, dict):
                    errors.append(f"'response_rules.patterns[{i}]' must be a dict")
                    continue
                if "name" not in item or not isinstance(item["name"], str) or not item["name"].strip():
                    errors.append(f"'response_rules.patterns[{i}].name' must be a non-empty string")
                if "pattern" not in item or not isinstance(item["pattern"], str) or not item["pattern"].strip():
                    errors.append(f"'response_rules.patterns[{i}].pattern' must be a non-empty string")

    return errors


def _validate_tool_change_rules(rules: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(rules, dict):
        return ["'tool_change_rules' must be a dict"]

    if "enabled" in rules and not isinstance(rules["enabled"], bool):
        errors.append("'tool_change_rules.enabled' must be boolean")
    if "action" in rules and rules["action"] not in {"warn", "block"}:
        errors.append("'tool_change_rules.action' must be one of ['warn', 'block']")
    return errors

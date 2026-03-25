from __future__ import annotations

import json
import os
import re
import urllib.parse
import unicodedata
from base64 import b64decode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

import yaml

from intent_guard.sdk.providers import GuardrailProvider, SemanticProviderUnavailable


@dataclass
class GuardDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False
    semantic_score: float = 1.0
    decision_id: str = field(default_factory=lambda: str(uuid4()))
    code: str = "ALLOW_POLICY"
    severity: str = "info"
    policy_name: str = "default-policy"
    policy_version: str = "unspecified"
    rule_id: str = "policy.default"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    override: dict[str, Any] | None = None
    semantic_prompt_version: str | None = None


class IntentGuardEngine:
    def __init__(self, policy: dict[str, Any], provider: GuardrailProvider | None = None):
        self.policy = policy or {}
        self.provider = provider

    def reload_policy(self, policy: dict[str, Any]) -> None:
        """Hot-swap the policy dict. In-flight evaluations may use old policy."""
        self.policy = policy

    @classmethod
    def from_policy_file(cls, policy_path: str | Path, provider: GuardrailProvider | None = None) -> "IntentGuardEngine":
        with open(policy_path, "r", encoding="utf-8") as handle:
            policy = yaml.safe_load(handle) or {}
        from intent_guard.sdk.validator import validate_policy

        errors = validate_policy(policy)
        if errors:
            import sys

            for err in errors:
                sys.stderr.write(f"Policy warning: {err}\\n")
        return cls(policy=policy, provider=provider)

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        task_context: str | None = None,
        semantic_example_name: str | None = None,
    ) -> GuardDecision:
        arguments = arguments or {}
        static_decision = self._run_static_checks(tool_name, arguments)
        if not static_decision.allowed:
            return static_decision

        semantic_decision = self._run_semantic_checks(tool_name, arguments, task_context, semantic_example_name)
        if semantic_decision is not None:
            return semantic_decision
        return self._decision(
            allowed=True,
            reason="allowed by policy",
            code="ALLOW_POLICY",
            severity="info",
            rule_id="policy.default",
        )

    def _run_static_checks(self, tool_name: str, arguments: dict[str, Any]) -> GuardDecision:
        static_rules = self.policy.get("static_rules", {})
        decode_arguments = bool(static_rules.get("decode_arguments", True))
        argument_variants = self._extract_argument_variants(arguments, decode=decode_arguments)
        forbidden_tools = set(static_rules.get("forbidden_tools", []))
        if tool_name in forbidden_tools:
            return self._decision(
                allowed=False,
                reason=f"tool '{tool_name}' is forbidden",
                requires_approval=True,
                code="BLOCK_FORBIDDEN_TOOL",
                severity="high",
                rule_id="static.forbidden_tools",
            )

        max_tokens = static_rules.get("max_tokens_per_call")
        token_count = self._extract_token_count(arguments)
        if isinstance(max_tokens, int) and token_count is not None and token_count > max_tokens:
            return self._decision(
                allowed=False,
                reason=f"token count {token_count} exceeds max {max_tokens}",
                requires_approval=True,
                code="BLOCK_TOKEN_LIMIT",
                severity="medium",
                rule_id="static.max_tokens_per_call",
            )

        protected_paths = static_rules.get("protected_paths", [])
        if protected_paths:
            for path in self._extract_path_candidates(arguments, decode=decode_arguments):
                for pattern in protected_paths:
                    if self._matches_path(path, pattern):
                        return self._decision(
                            allowed=False,
                            reason=f"path '{path}' matches protected pattern '{pattern}'",
                            requires_approval=True,
                            code="BLOCK_PROTECTED_PATH",
                            severity="high",
                            rule_id="static.protected_paths",
                        )

        for index, rule in enumerate(self._iter_custom_policies(), start=1):
            if rule.get("tool_name") != tool_name:
                continue

            args_rule = rule.get("args", {})
            required_args = args_rule.get("all_present", [])
            missing = [name for name in required_args if name not in arguments]
            if missing:
                return self._decision(
                    allowed=False,
                    reason=f"tool '{tool_name}' is missing required arguments: {', '.join(missing)}",
                    requires_approval=True,
                    code="BLOCK_CUSTOM_POLICY_MISSING_ARGS",
                    severity="medium",
                    rule_id=f"custom_policies.{index}.args.all_present",
                )

            forbidden_args = args_rule.get("should_not_present", [])
            present_forbidden = [name for name in forbidden_args if name in arguments]
            if present_forbidden:
                return self._decision(
                    allowed=False,
                    reason=f"tool '{tool_name}' contains forbidden arguments: {', '.join(present_forbidden)}",
                    requires_approval=True,
                    code="BLOCK_CUSTOM_POLICY_FORBIDDEN_ARGS",
                    severity="high",
                    rule_id=f"custom_policies.{index}.args.should_not_present",
                )

        injection_patterns = static_rules.get("injection_patterns", [])
        if injection_patterns:
            decision = self._match_pattern_block(
                argument_variants=argument_variants,
                patterns=injection_patterns,
                code="BLOCK_INJECTION_DETECTED",
                rule_id="static.injection_patterns",
                reason_template="potential injection detected in argument: pattern '{pattern}' matched",
                severity="high",
            )
            if decision is not None:
                return decision

        sensitive_patterns = static_rules.get("sensitive_data_patterns", [])
        if sensitive_patterns:
            for variant in argument_variants:
                for pat_config in sensitive_patterns:
                    pat_name = pat_config.get("name", "unknown")
                    pat_regex = pat_config.get("pattern", "")
                    if pat_regex and re.search(pat_regex, variant, re.IGNORECASE):
                        return self._decision(
                            allowed=False,
                            reason=f"sensitive data detected: {pat_name}",
                            requires_approval=True,
                            code="BLOCK_SENSITIVE_DATA",
                            severity="high",
                            rule_id="static.sensitive_data_patterns",
                        )

        return self._decision(
            allowed=True,
            reason="static checks passed",
            code="ALLOW_STATIC",
            severity="info",
            rule_id="static.passed",
        )

    def _match_pattern_block(
        self,
        argument_variants: list[str],
        patterns: list[str],
        code: str,
        rule_id: str,
        reason_template: str,
        severity: str,
    ) -> GuardDecision | None:
        for value in argument_variants:
            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return self._decision(
                        allowed=False,
                        reason=reason_template.format(pattern=pattern),
                        code=code,
                        severity=severity,
                        rule_id=rule_id,
                    )
        return None

    def _iter_custom_policies(self) -> Iterable[dict[str, Any]]:
        raw_custom_policies = self.policy.get("custom_policies", [])
        if isinstance(raw_custom_policies, dict):
            return [raw_custom_policies]
        if not isinstance(raw_custom_policies, list):
            return []
        return [rule for rule in raw_custom_policies if isinstance(rule, dict)]

    def _run_semantic_checks(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        task_context: str | None,
        semantic_example_name: str | None = None,
    ) -> GuardDecision | None:
        semantic_rules = self.policy.get("semantic_rules", {})
        if not semantic_rules:
            return None

        mode = self._normalize_semantic_mode(semantic_rules.get("mode", "enforce"))
        if mode == "off":
            return None
        if self.provider is None:
            return self._semantic_provider_failure_decision(
                tool_name=tool_name,
                semantic_rules=semantic_rules,
                reason="semantic provider is not configured",
            )

        threshold = float(semantic_rules.get("critical_intent_threshold", 0.85))
        prompt_version = str(semantic_rules.get("prompt_version", "v1"))
        prompt = self._build_semantic_prompt(
            tool_name,
            arguments,
            task_context,
            semantic_rules.get("constraints", []),
            prompt_version,
            semantic_example_name,
        )
        try:
            verdict = self.provider.judge(prompt)
        except SemanticProviderUnavailable as exc:
            return self._semantic_provider_failure_decision(
                tool_name=tool_name,
                semantic_rules=semantic_rules,
                reason=str(exc) or "semantic provider failed",
            )

        if verdict.safe and verdict.score >= threshold:
            return self._decision(
                allowed=True,
                reason="semantic checks passed",
                semantic_score=verdict.score,
                code="ALLOW_SEMANTIC",
                severity="info",
                rule_id="semantic.threshold",
                semantic_prompt_version=prompt_version,
            )
        if mode == "advisory":
            advisory_reason = verdict.reason or f"semantic advisory alert (score={verdict.score:.2f})"
            return self._decision(
                allowed=True,
                reason=advisory_reason,
                semantic_score=verdict.score,
                code="ALLOW_SEMANTIC_ADVISORY",
                severity="warning",
                rule_id="semantic.advisory",
                semantic_prompt_version=prompt_version,
            )
        blocked_reason = verdict.reason or f"semantic check failed (score={verdict.score:.2f})"
        return self._decision(
            allowed=False,
            reason=blocked_reason,
            requires_approval=True,
            semantic_score=verdict.score,
            code="BLOCK_SEMANTIC",
            severity="high",
            rule_id="semantic.threshold",
            semantic_prompt_version=prompt_version,
        )

    def _semantic_provider_failure_decision(
        self,
        tool_name: str,
        semantic_rules: dict[str, Any],
        reason: str,
    ) -> GuardDecision:
        fail_mode = self._semantic_provider_fail_mode(semantic_rules, tool_name)
        if fail_mode == "enforce":
            return self._decision(
                allowed=False,
                reason=f"semantic provider unavailable: {reason}",
                requires_approval=True,
                code="BLOCK_SEMANTIC_PROVIDER_FAILURE",
                severity="high",
                rule_id="semantic.provider_failure",
            )
        return self._decision(
            allowed=True,
            reason=f"semantic provider unavailable ({fail_mode} fail mode): {reason}",
            code="ALLOW_SEMANTIC_PROVIDER_FAILURE",
            severity="warning" if fail_mode == "advisory" else "info",
            rule_id="semantic.provider_failure",
        )

    def _semantic_provider_fail_mode(self, semantic_rules: dict[str, Any], tool_name: str) -> str:
        configured = semantic_rules.get("provider_fail_mode", "advisory")
        if isinstance(configured, dict):
            by_tool = configured.get("by_tool", {})
            if isinstance(by_tool, dict):
                specific = by_tool.get(tool_name)
                if specific is not None:
                    return self._normalize_semantic_mode(specific)
            return self._normalize_semantic_mode(configured.get("default", "advisory"))
        return self._normalize_semantic_mode(configured)

    @staticmethod
    def _normalize_semantic_mode(value: Any) -> str:
        normalized = str(value or "enforce").strip().lower()
        if normalized in {"off", "enforce", "advisory"}:
            return normalized
        return "enforce"

    def build_override_decision(self, override: dict[str, Any] | None = None) -> GuardDecision:
        normalized = self._normalize_override(override)
        return self._decision(
            allowed=True,
            reason="approved by user",
            requires_approval=False,
            code="ALLOW_OVERRIDE",
            severity="warning",
            rule_id="override.manual",
            override=normalized,
        )

    def _decision(self, allowed: bool, reason: str, **kwargs: Any) -> GuardDecision:
        return GuardDecision(
            allowed=allowed,
            reason=reason,
            policy_name=str(self.policy.get("name", "default-policy")),
            policy_version=str(self.policy.get("version", "unspecified")),
            **kwargs,
        )

    @staticmethod
    def _normalize_override(override: dict[str, Any] | None) -> dict[str, Any]:
        override = override or {}
        return {
            "who": override.get("who"),
            "why": override.get("why"),
            "ttl": override.get("ttl"),
        }

    @staticmethod
    def _extract_token_count(arguments: dict[str, Any]) -> int | None:
        for key in ("max_tokens", "tokens", "token_count"):
            value = arguments.get(key)
            if isinstance(value, int):
                return value
        return None

    def _extract_all_strings(self, value: Any) -> Iterable[str]:
        if isinstance(value, dict):
            for nested in value.values():
                yield from self._extract_all_strings(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from self._extract_all_strings(nested)
        elif isinstance(value, str):
            yield value

    def _extract_argument_variants(self, arguments: dict[str, Any], decode: bool) -> list[str]:
        variants: list[str] = []
        for value in self._extract_all_strings(arguments):
            variants.append(value)
            if decode:
                variants.extend(self._decode_variants(value))
        return variants

    @staticmethod
    def _decode_variants(value: str) -> list[str]:
        decoded: list[str] = []

        url_decoded = urllib.parse.unquote(value)
        if url_decoded != value:
            decoded.append(url_decoded)

        unicode_normalized = unicodedata.normalize("NFKC", value)
        if unicode_normalized != value:
            decoded.append(unicode_normalized)

        b64 = IntentGuardEngine._try_base64_decode(value)
        if b64 is not None and b64 != value:
            decoded.append(b64)
        return decoded

    @staticmethod
    def _try_base64_decode(value: str) -> str | None:
        candidate = value.strip()
        if len(candidate) < 12:
            return None
        candidate = candidate.replace("-", "+").replace("_", "/")
        if len(candidate) % 4:
            candidate += "=" * (4 - (len(candidate) % 4))
        try:
            decoded = b64decode(candidate, validate=True)
            text = decoded.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        return text if text else None

    def _extract_path_candidates(self, value: Any, parent_key: str = "", decode: bool = False) -> Iterable[str]:
        if isinstance(value, dict):
            for key, nested in value.items():
                yield from self._extract_path_candidates(nested, parent_key=key, decode=decode)
        elif isinstance(value, list):
            for nested in value:
                yield from self._extract_path_candidates(nested, parent_key=parent_key, decode=decode)
        elif isinstance(value, str) and self._looks_like_path(value, parent_key):
            yield value
            if decode:
                for decoded_value in self._decode_variants(value):
                    if self._looks_like_path(decoded_value, parent_key):
                        yield decoded_value

    @staticmethod
    def _looks_like_path(value: str, parent_key: str) -> bool:
        key = parent_key.lower()
        if any(marker in key for marker in ("path", "file", "filename", "target")):
            return True
        return "/" in value or value.startswith(".")

    @staticmethod
    def _matches_path(path: str, pattern: str) -> bool:
        normalized_path = os.path.normpath(path)
        normalized_pattern = os.path.normpath(pattern)
        return (
            fnmatch(path, pattern)
            or fnmatch(normalized_path, normalized_pattern)
            or normalized_path == normalized_pattern
            or path == pattern
        )

    @staticmethod
    def _build_semantic_prompt(
        tool_name: str,
        arguments: dict[str, Any],
        task_context: str | None,
        constraints: list[dict[str, Any]],
        prompt_version: str,
        semantic_example_name: str | None = None,
    ) -> str:
        constraint_text = json.dumps(constraints, indent=2, sort_keys=True)
        return (
            "You are a policy guardrail evaluator.\n"
            f"PromptVersion: {prompt_version}\n"
            f"ExampleName: {semantic_example_name or 'none'}\n"
            f"Task: {task_context or 'No task context supplied'}\n"
            f"ToolName: {tool_name}\n"
            f"Arguments: {json.dumps(arguments, sort_keys=True)}\n"
            f"PolicyConstraints: {constraint_text}\n\n"
            "Return a strict JSON object only with keys:\n"
            '  {"safe": <boolean>, "score": <number 0.0..1.0>, "reason": <string>}\n'
            "Rules:\n"
            "- safe=true only when call is policy-aligned with low risk.\n"
            "- score is confidence that the call is safe under constraints.\n"
            "- reason must be concise and specific.\n"
            "- No markdown, no extra text."
        )

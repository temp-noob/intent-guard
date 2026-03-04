from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Iterable

import yaml

from intent_guard.sdk.providers import GuardrailProvider


@dataclass
class GuardDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False
    semantic_score: float = 1.0


class IntentGuardEngine:
    def __init__(self, policy: dict[str, Any], provider: GuardrailProvider | None = None):
        self.policy = policy or {}
        self.provider = provider

    @classmethod
    def from_policy_file(cls, policy_path: str | Path, provider: GuardrailProvider | None = None) -> "IntentGuardEngine":
        with open(policy_path, "r", encoding="utf-8") as handle:
            policy = yaml.safe_load(handle) or {}
        return cls(policy=policy, provider=provider)

    def evaluate_tool_call(self, tool_name: str, arguments: dict[str, Any] | None, task_context: str | None = None) -> GuardDecision:
        arguments = arguments or {}
        static_decision = self._run_static_checks(tool_name, arguments)
        if not static_decision.allowed:
            return static_decision

        semantic_decision = self._run_semantic_checks(tool_name, arguments, task_context)
        if semantic_decision is not None:
            return semantic_decision
        return GuardDecision(allowed=True, reason="allowed by policy")

    def _run_static_checks(self, tool_name: str, arguments: dict[str, Any]) -> GuardDecision:
        static_rules = self.policy.get("static_rules", {})
        forbidden_tools = set(static_rules.get("forbidden_tools", []))
        if tool_name in forbidden_tools:
            return GuardDecision(False, f"tool '{tool_name}' is forbidden", requires_approval=True)

        max_tokens = static_rules.get("max_tokens_per_call")
        token_count = self._extract_token_count(arguments)
        if isinstance(max_tokens, int) and token_count is not None and token_count > max_tokens:
            return GuardDecision(False, f"token count {token_count} exceeds max {max_tokens}", requires_approval=True)

        protected_paths = static_rules.get("protected_paths", [])
        if protected_paths:
            for path in self._extract_path_candidates(arguments):
                for pattern in protected_paths:
                    if self._matches_path(path, pattern):
                        return GuardDecision(False, f"path '{path}' matches protected pattern '{pattern}'", requires_approval=True)

        return GuardDecision(True, "static checks passed")

    def _run_semantic_checks(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        task_context: str | None,
    ) -> GuardDecision | None:
        semantic_rules = self.policy.get("semantic_rules", {})
        if not semantic_rules or self.provider is None:
            return None

        threshold = float(semantic_rules.get("critical_intent_threshold", 0.85))
        prompt = self._build_semantic_prompt(tool_name, arguments, task_context, semantic_rules.get("constraints", []))
        verdict = self.provider.judge(prompt)
        if verdict.safe and verdict.score >= threshold:
            return GuardDecision(True, "semantic checks passed", semantic_score=verdict.score)
        return GuardDecision(
            False,
            f"semantic check failed (score={verdict.score:.2f})",
            requires_approval=True,
            semantic_score=verdict.score,
        )

    @staticmethod
    def _extract_token_count(arguments: dict[str, Any]) -> int | None:
        for key in ("max_tokens", "tokens", "token_count"):
            value = arguments.get(key)
            if isinstance(value, int):
                return value
        return None

    def _extract_path_candidates(self, value: Any, parent_key: str = "") -> Iterable[str]:
        if isinstance(value, dict):
            for key, nested in value.items():
                yield from self._extract_path_candidates(nested, parent_key=key)
        elif isinstance(value, list):
            for nested in value:
                yield from self._extract_path_candidates(nested, parent_key=parent_key)
        elif isinstance(value, str) and self._looks_like_path(value, parent_key):
            yield value

    @staticmethod
    def _looks_like_path(value: str, parent_key: str) -> bool:
        key = parent_key.lower()
        if any(marker in key for marker in ("path", "file", "filename", "target")):
            return True
        return "/" in value or value.startswith(".")

    @staticmethod
    def _matches_path(path: str, pattern: str) -> bool:
        normalized_path = path.lstrip("./")
        normalized_pattern = pattern.lstrip("./")
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
    ) -> str:
        constraint_text = json.dumps(constraints, indent=2, sort_keys=True)
        return (
            f"Task: {task_context or 'No task context supplied'}\n"
            f"Tool Call: {tool_name}({json.dumps(arguments, sort_keys=True)})\n"
            f"Policy Constraints:\n{constraint_text}\n\n"
            "Decide whether this action is SAFE or UNSAFE under the policy. "
            "Respond with SAFE or UNSAFE and include a score from 0.0 to 1.0."
        )

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.mcp_proxy import MCPProxy
from intent_guard.sdk.providers import GuardrailProvider, LiteLLMProvider, OllamaProvider


class IntentGuardSDK:
    def __init__(
        self,
        policy_path: str | Path,
        local_model: str | None = None,
        provider: GuardrailProvider | None = None,
        task_context: str | None = None,
        approval_callback: Callable[[Any, dict[str, Any]], bool] | None = None,
    ):
        resolved_provider = provider
        if resolved_provider is None and local_model:
            resolved_provider = OllamaProvider(local_model)
        if resolved_provider is None and os.environ.get("LLM_MODEL"):
            resolved_provider = LiteLLMProvider()
        self.engine = IntentGuardEngine.from_policy_file(policy_path=policy_path, provider=resolved_provider)
        self.task_context = task_context
        self.approval_callback = approval_callback

    def evaluate(self, tool_name: str, arguments: dict[str, Any] | None = None):
        return self.engine.evaluate_tool_call(tool_name=tool_name, arguments=arguments or {}, task_context=self.task_context)

    def create_proxy(self, target_command: list[str]) -> MCPProxy:
        return MCPProxy(
            engine=self.engine,
            target_command=target_command,
            approval_callback=self.approval_callback,
            task_context=self.task_context,
        )

from __future__ import annotations

import copy
import re
from typing import Any


class LogRedactor:
    """Redacts sensitive values from log dicts based on configured patterns.

    Thread-safe: all state is set during __init__ and never mutated afterwards.
    """

    def __init__(self, sensitive_data_patterns: list[dict[str, str]]) -> None:
        self._compiled: list[tuple[str, re.Pattern[str]]] = []
        for item in sensitive_data_patterns:
            name = item.get("name", "unknown")
            pattern = item.get("pattern", "")
            if pattern:
                try:
                    self._compiled.append((name, re.compile(pattern, re.IGNORECASE)))
                except re.error:
                    continue

    def redact(self, data: dict[str, Any]) -> dict[str, Any]:
        """Return a deep copy of *data* with sensitive string values replaced."""
        cloned = copy.deepcopy(data)
        return self._walk(cloned)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _walk(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: self._walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(item) for item in value]
        if isinstance(value, str):
            return self._redact_string(value)
        return value

    def _redact_string(self, value: str) -> str:
        for name, pattern in self._compiled:
            if pattern.search(value):
                value = pattern.sub(f"[REDACTED:{name}]", value)
        return value

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolRateLimit:
    max_calls: int
    window_seconds: float


class ToolRateLimiter:
    """Sliding-window rate limiter keyed by tool name.

    Each tool maintains a deque of timestamps.  On ``check()``, expired
    entries are pruned and the call is allowed only when the remaining
    count is below the configured maximum for the window.
    """

    def __init__(
        self,
        enabled: bool = True,
        default: ToolRateLimit | None = None,
        by_tool: dict[str, ToolRateLimit] | None = None,
    ):
        self._enabled = enabled
        self._default = default
        self._by_tool: dict[str, ToolRateLimit] = by_tool or {}
        self._windows: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "ToolRateLimiter":
        """Build a limiter from the ``rate_limits`` policy section.

        Expected shape::

            rate_limits:
              enabled: 1  # opt-in
              default:
                max_calls: 60
                window_seconds: 60
              by_tool:
                write_file:
                  max_calls: 10
                  window_seconds: 60
        """
        enabled_value = config.get("enabled")
        if isinstance(enabled_value, bool):
            enabled = enabled_value
        elif isinstance(enabled_value, int) and not isinstance(enabled_value, bool):
            enabled = enabled_value != 0
        else:
            enabled = False
        if not enabled:
            return cls(enabled=False)

        default_cfg = config.get("default")
        default = (
            ToolRateLimit(
                max_calls=int(default_cfg["max_calls"]),
                window_seconds=float(default_cfg["window_seconds"]),
            )
            if default_cfg
            else None
        )
        by_tool: dict[str, ToolRateLimit] = {}
        for tool_name, tool_cfg in (config.get("by_tool") or {}).items():
            by_tool[tool_name] = ToolRateLimit(
                max_calls=int(tool_cfg["max_calls"]),
                window_seconds=float(tool_cfg["window_seconds"]),
            )
        return cls(enabled=True, default=default, by_tool=by_tool)

    def _limit_for(self, tool_name: str) -> ToolRateLimit | None:
        return self._by_tool.get(tool_name, self._default)

    def check(self, tool_name: str, now: float | None = None) -> tuple[bool, str]:
        """Return ``(allowed, reason)``.

        An optional *now* parameter supports deterministic testing.
        """
        if not self._enabled:
            return True, "rate limiting disabled"

        limit = self._limit_for(tool_name)
        if limit is None:
            return True, "no rate limit configured"

        current_time = time.time() if now is None else now
        cutoff = current_time - limit.window_seconds

        with self._lock:
            window = self._windows.setdefault(tool_name, deque())
            # Prune expired entries
            while window and window[0] <= cutoff:
                window.popleft()

            if len(window) >= limit.max_calls:
                return (
                    False,
                    f"tool '{tool_name}' exceeded rate limit: "
                    f"{limit.max_calls} calls per {limit.window_seconds}s window",
                )

            window.append(current_time)
            return True, "rate limit ok"

    def reset(self, tool_name: str | None = None) -> None:
        """Clear recorded timestamps.

        If *tool_name* is ``None``, all windows are cleared.
        """
        with self._lock:
            if tool_name is None:
                self._windows.clear()
            else:
                self._windows.pop(tool_name, None)

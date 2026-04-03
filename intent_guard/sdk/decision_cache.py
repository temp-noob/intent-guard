from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from intent_guard.sdk.providers import SemanticVerdict


@dataclass
class CacheEntry:
    verdict: SemanticVerdict
    expires_at: float


class SemanticDecisionCache:
    def __init__(self, max_size: int = 256, ttl_seconds: int = 300):
        self.max_size = max(1, int(max_size))
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._items: OrderedDict[str, CacheEntry] = OrderedDict()

    def make_key(self, tool_name: str, arguments: dict[str, Any], task_context: str | None) -> str:
        payload = {
            "tool_name": tool_name,
            "arguments": arguments,
            "task_context": task_context or "",
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def get(self, key: str, now: float | None = None) -> SemanticVerdict | None:
        current_time = time.time() if now is None else now
        entry = self._items.get(key)
        if entry is None:
            return None
        if entry.expires_at <= current_time:
            self._items.pop(key, None)
            return None
        self._items.move_to_end(key)
        return entry.verdict

    def set(self, key: str, verdict: SemanticVerdict, now: float | None = None) -> None:
        current_time = time.time() if now is None else now
        self._items[key] = CacheEntry(verdict=verdict, expires_at=current_time + self.ttl_seconds)
        self._items.move_to_end(key)
        while len(self._items) > self.max_size:
            self._items.popitem(last=False)

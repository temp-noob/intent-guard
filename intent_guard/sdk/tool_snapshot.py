from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class ToolSnapshotStore:
    def __init__(self, root_dir: str | Path | None = None):
        base = Path(root_dir) if root_dir is not None else Path(".intent-guard") / "tool-snapshots"
        self.root_dir = base
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def check_or_store(self, server_id: str, tools_payload: dict[str, Any]) -> tuple[bool, str]:
        normalized = self._normalize_payload(tools_payload)
        snapshot_path = self._snapshot_path(server_id)
        if not snapshot_path.exists():
            snapshot_path.write_text(json.dumps(normalized, sort_keys=True, indent=2), encoding="utf-8")
            return (True, "tool snapshot created")

        previous = json.loads(snapshot_path.read_text(encoding="utf-8"))
        if previous == normalized:
            return (True, "tool snapshot unchanged")
        snapshot_path.write_text(json.dumps(normalized, sort_keys=True, indent=2), encoding="utf-8")
        return (False, "tool metadata changed since last snapshot")

    @staticmethod
    def _normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
        tools = payload.get("result", {}).get("tools", [])
        normalized_tools = []
        if isinstance(tools, list):
            for item in tools:
                if not isinstance(item, dict):
                    continue
                normalized_tools.append(
                    {
                        "name": item.get("name"),
                        "description": item.get("description"),
                        "inputSchema": item.get("inputSchema"),
                    }
                )
        normalized_tools.sort(key=lambda item: str(item.get("name", "")))
        return {"tools": normalized_tools}

    def _snapshot_path(self, server_id: str) -> Path:
        digest = hashlib.sha256(server_id.encode("utf-8")).hexdigest()
        return self.root_dir / f"{digest}.json"

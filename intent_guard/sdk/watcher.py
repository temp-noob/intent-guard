from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable

import yaml


class PolicyWatcher:
    """Watches a policy YAML file for changes and triggers a reload callback."""

    def __init__(
        self,
        policy_path: str | Path,
        on_reload: Callable[[dict[str, Any]], None],
        poll_interval: float = 2.0,
        logger: Callable[[str], None] | None = None,
    ):
        self.policy_path = Path(policy_path)
        self.on_reload = on_reload
        self.poll_interval = poll_interval
        self.logger = logger or (lambda msg: sys.stderr.write(msg + "\n"))
        self._last_mtime: float = 0.0
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._last_mtime = self._get_mtime()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def _get_mtime(self) -> float:
        try:
            return os.path.getmtime(self.policy_path)
        except OSError:
            return 0.0

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self.poll_interval)
            if self._stop_event.is_set():
                break
            current_mtime = self._get_mtime()
            if current_mtime > self._last_mtime:
                self._last_mtime = current_mtime
                self._try_reload()

    def _try_reload(self) -> None:
        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                new_policy = yaml.safe_load(f) or {}
            self.logger(f"Policy reloaded from {self.policy_path}")
            self.on_reload(new_policy)
        except Exception as exc:
            self.logger(f"Policy reload failed: {exc}")

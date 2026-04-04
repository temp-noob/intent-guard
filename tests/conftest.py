from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    markexpr = str(config.getoption("-m") or "")
    if "runOllamaProvider" in markexpr:
        return

    skip_marker = pytest.mark.skip(reason="requires explicit selection: pytest -m runOllamaProvider")
    for item in items:
        if item.get_closest_marker("runOllamaProvider"):
            item.add_marker(skip_marker)

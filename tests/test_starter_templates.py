"""Validation tests for starter policy templates in policies/."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from intent_guard.sdk.engine import IntentGuardEngine

POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"
TEMPLATE_FILES = sorted(POLICIES_DIR.glob("*.yaml"))


@pytest.fixture(params=[p.name for p in TEMPLATE_FILES], ids=[p.stem for p in TEMPLATE_FILES])
def template_path(request: pytest.FixtureRequest) -> Path:
    return POLICIES_DIR / request.param


# ── Loading & structure ──────────────────────────────────────────────


def test_yaml_loads_without_error(template_path: Path) -> None:
    data = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_has_required_fields(template_path: Path) -> None:
    data = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    assert "version" in data, "missing 'version'"
    assert "name" in data, "missing 'name'"


def test_engine_loads_from_template(template_path: Path) -> None:
    engine = IntentGuardEngine.from_policy_file(template_path)
    assert engine is not None


def test_engine_evaluates_safe_call(template_path: Path) -> None:
    engine = IntentGuardEngine.from_policy_file(template_path)
    decision = engine.evaluate_tool_call("read_file", {"path": "src/main.py"})
    assert decision.allowed is True


# ── Behavioural checks (at least one template must satisfy each) ─────


def _load_all_engines() -> list[tuple[str, IntentGuardEngine]]:
    return [
        (p.stem, IntentGuardEngine.from_policy_file(p))
        for p in TEMPLATE_FILES
    ]


def test_at_least_one_blocks_forbidden_tool() -> None:
    blocked = False
    for name, engine in _load_all_engines():
        decision = engine.evaluate_tool_call("delete_database", {})
        if not decision.allowed:
            blocked = True
            break
    assert blocked, "No template blocked the forbidden tool 'delete_database'"


def test_at_least_one_blocks_protected_path() -> None:
    blocked = False
    for name, engine in _load_all_engines():
        decision = engine.evaluate_tool_call("write_file", {"path": ".env"})
        if not decision.allowed:
            blocked = True
            break
    assert blocked, "No template blocked a write to the protected path '.env'"

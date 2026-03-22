from __future__ import annotations

import time

import yaml

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.watcher import PolicyWatcher


POLL_INTERVAL = 0.1
WAIT_TIME = 0.5


def _write_policy(path, policy: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(policy, f)


def test_watcher_detects_file_change(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    initial_policy = {"name": "v1"}
    _write_policy(policy_file, initial_policy)

    received: list[dict] = []
    watcher = PolicyWatcher(
        policy_path=policy_file,
        on_reload=lambda p: received.append(p),
        poll_interval=POLL_INTERVAL,
    )
    watcher.start()
    try:
        time.sleep(WAIT_TIME)
        assert received == [], "should not reload if file unchanged"

        new_policy = {"name": "v2", "static_rules": {"forbidden_tools": ["rm"]}}
        _write_policy(policy_file, new_policy)

        time.sleep(WAIT_TIME)
        assert len(received) == 1
        assert received[0]["name"] == "v2"
        assert received[0]["static_rules"]["forbidden_tools"] == ["rm"]
    finally:
        watcher.stop()


def test_watcher_ignores_unchanged_file(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, {"name": "stable"})

    call_count = 0

    def on_reload(p):
        nonlocal call_count
        call_count += 1

    watcher = PolicyWatcher(
        policy_path=policy_file,
        on_reload=on_reload,
        poll_interval=POLL_INTERVAL,
    )
    watcher.start()
    try:
        time.sleep(WAIT_TIME * 2)
        assert call_count == 0, "on_reload should not be called when file is unchanged"
    finally:
        watcher.stop()


def test_watcher_handles_invalid_yaml(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, {"name": "good"})

    received: list[dict] = []
    logged: list[str] = []

    watcher = PolicyWatcher(
        policy_path=policy_file,
        on_reload=lambda p: received.append(p),
        poll_interval=POLL_INTERVAL,
        logger=lambda msg: logged.append(msg),
    )
    watcher.start()
    try:
        time.sleep(WAIT_TIME)

        with open(policy_file, "w", encoding="utf-8") as f:
            f.write(":\n  - :\n    bad: [unterminated\n")

        time.sleep(WAIT_TIME)
        assert len(received) == 0, "invalid YAML should not trigger on_reload"
        assert any("reload failed" in msg for msg in logged)
    finally:
        watcher.stop()


def test_engine_reload_policy():
    initial_policy = {
        "name": "initial",
        "static_rules": {"forbidden_tools": ["dangerous_tool"]},
    }
    engine = IntentGuardEngine(policy=initial_policy)

    decision = engine.evaluate_tool_call("dangerous_tool", {})
    assert not decision.allowed

    new_policy = {
        "name": "updated",
        "static_rules": {"forbidden_tools": []},
    }
    engine.reload_policy(new_policy)

    decision = engine.evaluate_tool_call("dangerous_tool", {})
    assert decision.allowed
    assert engine.policy["name"] == "updated"


def test_watcher_stop(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    _write_policy(policy_file, {"name": "test"})

    watcher = PolicyWatcher(
        policy_path=policy_file,
        on_reload=lambda p: None,
        poll_interval=POLL_INTERVAL,
    )
    watcher.start()
    assert watcher._thread is not None
    assert watcher._thread.is_alive()

    watcher.stop()
    assert not watcher._thread.is_alive()

"""Tests for per-tool sliding-window rate limiting."""

from __future__ import annotations

import threading

import pytest

from intent_guard.sdk.rate_limiter import ToolRateLimiter, ToolRateLimit
from intent_guard.sdk.engine import IntentGuardEngine


# ---------------------------------------------------------------------------
# ToolRateLimiter unit tests
# ---------------------------------------------------------------------------


class TestToolRateLimiterDefaults:
    """Default rate limit enforcement."""

    def test_no_config_always_allows(self):
        limiter = ToolRateLimiter()
        allowed, reason = limiter.check("any_tool", now=0.0)
        assert allowed is True
        assert "no rate limit" in reason

    def test_default_limit_blocks_after_max(self):
        limiter = ToolRateLimiter(default=ToolRateLimit(max_calls=3, window_seconds=10))
        now = 100.0
        for _ in range(3):
            allowed, _ = limiter.check("some_tool", now=now)
            assert allowed is True
        allowed, reason = limiter.check("some_tool", now=now)
        assert allowed is False
        assert "exceeded rate limit" in reason

    def test_default_applies_to_all_tools(self):
        limiter = ToolRateLimiter(default=ToolRateLimit(max_calls=1, window_seconds=10))
        now = 100.0
        allowed, _ = limiter.check("tool_a", now=now)
        assert allowed is True
        allowed, _ = limiter.check("tool_a", now=now)
        assert allowed is False
        # Different tool still has its own window
        allowed, _ = limiter.check("tool_b", now=now)
        assert allowed is True


class TestToolRateLimiterPerTool:
    """Per-tool override rate limits."""

    def test_per_tool_overrides_default(self):
        limiter = ToolRateLimiter(
            default=ToolRateLimit(max_calls=100, window_seconds=60),
            by_tool={"write_file": ToolRateLimit(max_calls=2, window_seconds=60)},
        )
        now = 100.0
        for _ in range(2):
            allowed, _ = limiter.check("write_file", now=now)
            assert allowed is True
        allowed, reason = limiter.check("write_file", now=now)
        assert allowed is False
        assert "write_file" in reason

    def test_non_overridden_tool_uses_default(self):
        limiter = ToolRateLimiter(
            default=ToolRateLimit(max_calls=2, window_seconds=60),
            by_tool={"write_file": ToolRateLimit(max_calls=100, window_seconds=60)},
        )
        now = 100.0
        for _ in range(2):
            allowed, _ = limiter.check("read_file", now=now)
            assert allowed is True
        allowed, _ = limiter.check("read_file", now=now)
        assert allowed is False


class TestSlidingWindowExpiry:
    """Sliding window should expire old calls."""

    def test_calls_allowed_after_window_passes(self):
        limiter = ToolRateLimiter(default=ToolRateLimit(max_calls=2, window_seconds=10))
        # Fill up the window at t=100
        limiter.check("tool", now=100.0)
        limiter.check("tool", now=100.0)
        allowed, _ = limiter.check("tool", now=100.0)
        assert allowed is False

        # At t=111 (window_seconds=10), old entries expired
        allowed, _ = limiter.check("tool", now=111.0)
        assert allowed is True

    def test_partial_expiry(self):
        limiter = ToolRateLimiter(default=ToolRateLimit(max_calls=2, window_seconds=10))
        limiter.check("tool", now=100.0)
        limiter.check("tool", now=105.0)
        # At t=100 + 10 = 110, only the first entry expires; one slot opens
        allowed, _ = limiter.check("tool", now=111.0)
        assert allowed is True
        # Now full again
        allowed, _ = limiter.check("tool", now=111.0)
        assert allowed is False


class TestReset:
    """Rate limiter reset."""

    def test_reset_specific_tool(self):
        limiter = ToolRateLimiter(default=ToolRateLimit(max_calls=1, window_seconds=60))
        limiter.check("tool_a", now=100.0)
        limiter.check("tool_b", now=100.0)
        # Both exhausted
        allowed_a, _ = limiter.check("tool_a", now=100.0)
        allowed_b, _ = limiter.check("tool_b", now=100.0)
        assert allowed_a is False
        assert allowed_b is False

        limiter.reset("tool_a")
        allowed_a, _ = limiter.check("tool_a", now=100.0)
        allowed_b, _ = limiter.check("tool_b", now=100.0)
        assert allowed_a is True
        assert allowed_b is False

    def test_reset_all(self):
        limiter = ToolRateLimiter(default=ToolRateLimit(max_calls=1, window_seconds=60))
        limiter.check("tool_a", now=100.0)
        limiter.check("tool_b", now=100.0)
        limiter.reset()
        allowed_a, _ = limiter.check("tool_a", now=100.0)
        allowed_b, _ = limiter.check("tool_b", now=100.0)
        assert allowed_a is True
        assert allowed_b is True


class TestFromConfig:
    """Build limiter from policy config dict."""

    def test_from_config_without_enabled_is_disabled(self):
        limiter = ToolRateLimiter.from_config({
            "default": {"max_calls": 1, "window_seconds": 60},
        })
        allowed_first, _ = limiter.check("write_file", now=100.0)
        allowed_second, _ = limiter.check("write_file", now=100.0)
        assert allowed_first is True
        assert allowed_second is True

    def test_from_config_enabled_zero_disables_limiter(self):
        limiter = ToolRateLimiter.from_config({
            "enabled": 0,
            "default": {"max_calls": 1, "window_seconds": 60},
        })
        allowed_first, _ = limiter.check("write_file", now=100.0)
        allowed_second, reason = limiter.check("write_file", now=100.0)
        assert allowed_first is True
        assert allowed_second is True
        assert "disabled" in reason

    def test_from_config_enabled_false_disables_limiter(self):
        limiter = ToolRateLimiter.from_config({
            "enabled": False,
            "default": {"max_calls": 1, "window_seconds": 60},
        })
        allowed_first, _ = limiter.check("write_file", now=100.0)
        allowed_second, _ = limiter.check("write_file", now=100.0)
        assert allowed_first is True
        assert allowed_second is True

    def test_from_config_enabled_one_enables_limiter(self):
        limiter = ToolRateLimiter.from_config({
            "enabled": 1,
            "default": {"max_calls": 1, "window_seconds": 60},
        })
        allowed_first, _ = limiter.check("write_file", now=100.0)
        allowed_second, _ = limiter.check("write_file", now=100.0)
        assert allowed_first is True
        assert allowed_second is False

    def test_from_config_enabled_true_enables_limiter(self):
        limiter = ToolRateLimiter.from_config({
            "enabled": True,
            "default": {"max_calls": 1, "window_seconds": 60},
        })
        allowed_first, _ = limiter.check("write_file", now=100.0)
        allowed_second, _ = limiter.check("write_file", now=100.0)
        assert allowed_first is True
        assert allowed_second is False

    def test_from_config(self):
        config = {
            "enabled": 1,
            "default": {"max_calls": 60, "window_seconds": 60},
            "by_tool": {
                "write_file": {"max_calls": 10, "window_seconds": 60},
            },
        }
        limiter = ToolRateLimiter.from_config(config)
        assert limiter._default is not None
        assert limiter._default.max_calls == 60
        assert "write_file" in limiter._by_tool
        assert limiter._by_tool["write_file"].max_calls == 10


class TestThreadSafety:
    """Basic thread-safety sanity check."""

    def test_concurrent_checks(self):
        limiter = ToolRateLimiter(default=ToolRateLimit(max_calls=50, window_seconds=60))
        results: list[bool] = []
        lock = threading.Lock()

        def worker():
            allowed, _ = limiter.check("tool", now=100.0)
            with lock:
                results.append(allowed)

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(1 for r in results if r)
        blocked_count = sum(1 for r in results if not r)
        assert allowed_count == 50
        assert blocked_count == 50


# ---------------------------------------------------------------------------
# Engine integration tests
# ---------------------------------------------------------------------------


class TestEngineRateLimitIntegration:
    """Rate limiting wired through IntentGuardEngine."""

    def _make_engine(self, rate_limits: dict) -> IntentGuardEngine:
        policy = {
            "name": "test-policy",
            "version": "1.0",
            "static_rules": {
                "rate_limits": rate_limits,
            },
        }
        return IntentGuardEngine(policy=policy)

    def test_engine_blocks_after_limit(self):
        engine = self._make_engine({
            "enabled": 1,
            "default": {"max_calls": 2, "window_seconds": 60},
        })
        d1 = engine.evaluate_tool_call("read_file", {})
        d2 = engine.evaluate_tool_call("read_file", {})
        assert d1.allowed is True
        assert d2.allowed is True

        d3 = engine.evaluate_tool_call("read_file", {})
        assert d3.allowed is False
        assert d3.code == "BLOCK_RATE_LIMIT"
        assert d3.severity == "medium"

    def test_engine_rate_limits_enabled_zero_bypasses_check(self):
        engine = self._make_engine({
            "enabled": 0,
            "default": {"max_calls": 1, "window_seconds": 60},
        })
        d1 = engine.evaluate_tool_call("read_file", {})
        d2 = engine.evaluate_tool_call("read_file", {})
        d3 = engine.evaluate_tool_call("read_file", {})
        assert d1.allowed is True
        assert d2.allowed is True
        assert d3.allowed is True
        assert d3.code != "BLOCK_RATE_LIMIT"

    def test_engine_no_rate_limits_configured(self):
        engine = IntentGuardEngine(policy={"static_rules": {}})
        decision = engine.evaluate_tool_call("any_tool", {})
        assert decision.allowed is True

    def test_engine_reload_policy_rebuilds_limiter(self):
        engine = self._make_engine({
            "enabled": 1,
            "default": {"max_calls": 1, "window_seconds": 60},
        })
        engine.evaluate_tool_call("tool", {})
        d = engine.evaluate_tool_call("tool", {})
        assert d.allowed is False

        # Reload with higher limit — limiter should be fresh
        engine.reload_policy({
            "name": "test-policy",
            "version": "1.0",
            "static_rules": {
                "rate_limits": {
                    "enabled": 1,
                    "default": {"max_calls": 100, "window_seconds": 60},
                },
            },
        })
        d = engine.evaluate_tool_call("tool", {})
        assert d.allowed is True

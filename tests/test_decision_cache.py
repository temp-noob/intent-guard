from __future__ import annotations

from dataclasses import dataclass

from intent_guard.sdk.decision_cache import SemanticDecisionCache
from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.providers import SemanticVerdict


@dataclass
class CountingProvider:
    verdict: SemanticVerdict
    calls: int = 0

    def judge(self, _prompt: str) -> SemanticVerdict:
        self.calls += 1
        return self.verdict


def test_semantic_cache_hit_avoids_second_provider_call():
    provider = CountingProvider(verdict=SemanticVerdict(safe=True, score=0.95, raw='{"safe":true,"score":0.95}'))
    engine = IntentGuardEngine(
        policy={
            "semantic_rules": {
                "mode": "enforce",
                "critical_intent_threshold": 0.85,
                "decision_cache": {"enabled": True, "max_size": 16, "ttl_seconds": 300},
                "constraints": [],
            }
        },
        provider=provider,
    )

    first = engine.evaluate_tool_call("read_file", {"path": "README.md"}, "docs")
    second = engine.evaluate_tool_call("read_file", {"path": "README.md"}, "docs")
    assert first.allowed is True
    assert second.allowed is True
    assert provider.calls == 1


def test_semantic_cache_miss_for_different_arguments():
    provider = CountingProvider(verdict=SemanticVerdict(safe=True, score=0.95, raw='{"safe":true,"score":0.95}'))
    engine = IntentGuardEngine(
        policy={
            "semantic_rules": {
                "mode": "enforce",
                "critical_intent_threshold": 0.85,
                "decision_cache": {"enabled": True, "max_size": 16, "ttl_seconds": 300},
                "constraints": [],
            }
        },
        provider=provider,
    )

    engine.evaluate_tool_call("read_file", {"path": "README.md"}, "docs")
    engine.evaluate_tool_call("read_file", {"path": "CHANGELOG.md"}, "docs")
    assert provider.calls == 2


def test_semantic_cache_ttl_expiry():
    cache = SemanticDecisionCache(max_size=4, ttl_seconds=10)
    key = cache.make_key("tool", {"a": 1}, "ctx")
    verdict = SemanticVerdict(safe=True, score=1.0, raw='{"safe":true,"score":1.0}')
    cache.set(key, verdict, now=100)
    assert cache.get(key, now=105) is not None
    assert cache.get(key, now=111) is None


def test_semantic_cache_lru_eviction():
    cache = SemanticDecisionCache(max_size=2, ttl_seconds=300)
    v = SemanticVerdict(safe=True, score=1.0, raw='{"safe":true,"score":1.0}')
    k1 = cache.make_key("a", {"x": 1}, "ctx")
    k2 = cache.make_key("b", {"x": 2}, "ctx")
    k3 = cache.make_key("c", {"x": 3}, "ctx")
    cache.set(k1, v, now=1)
    cache.set(k2, v, now=2)
    _ = cache.get(k1, now=3)  # refresh k1
    cache.set(k3, v, now=4)  # evicts k2
    assert cache.get(k1, now=5) is not None
    assert cache.get(k2, now=5) is None
    assert cache.get(k3, now=5) is not None

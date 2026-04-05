"""Tests for v2 rubric-based semantic scoring."""
from __future__ import annotations

import json

import pytest

from intent_guard.sdk.engine import IntentGuardEngine, GuardDecision
from intent_guard.sdk.providers import (
    DEFAULT_RUBRIC_DIMENSIONS,
    DimensionResult,
    SemanticVerdict,
    compute_rubric_score,
    parse_rubric_verdict,
)


# ---------------------------------------------------------------------------
# Unit tests: DimensionResult and compute_rubric_score
# ---------------------------------------------------------------------------


class TestComputeRubricScore:
    def test_all_pass_equal_weights(self):
        dims = [
            DimensionResult("a", True),
            DimensionResult("b", True),
            DimensionResult("c", True),
            DimensionResult("d", True),
        ]
        assert compute_rubric_score(dims) == pytest.approx(1.0)

    def test_none_pass(self):
        dims = [
            DimensionResult("tool_task_alignment", False),
            DimensionResult("argument_scope_compliance", False),
            DimensionResult("no_forbidden_scope_violation", False),
            DimensionResult("no_side_effect_risk", False),
        ]
        assert compute_rubric_score(dims) == pytest.approx(0.0)

    def test_one_fail_default_weights(self):
        dims = [
            DimensionResult("tool_task_alignment", True),
            DimensionResult("argument_scope_compliance", True),
            DimensionResult("no_forbidden_scope_violation", False),
            DimensionResult("no_side_effect_risk", True),
        ]
        # Weight of no_forbidden_scope_violation = 0.30, total weight = 1.0
        # Score = (0.25 + 0.30 + 0.15) / 1.0 = 0.70
        assert compute_rubric_score(dims) == pytest.approx(0.70)

    def test_custom_weights(self):
        dims = [
            DimensionResult("a", True),
            DimensionResult("b", False),
        ]
        weights = {"a": 0.8, "b": 0.2}
        assert compute_rubric_score(dims, weights) == pytest.approx(0.8)

    def test_empty_dimensions(self):
        assert compute_rubric_score([]) == 0.0

    def test_single_dimension_pass(self):
        dims = [DimensionResult("tool_task_alignment", True)]
        assert compute_rubric_score(dims) == pytest.approx(1.0)

    def test_single_dimension_fail(self):
        dims = [DimensionResult("tool_task_alignment", False)]
        assert compute_rubric_score(dims) == pytest.approx(0.0)

    def test_unknown_dimension_uses_default_weight(self):
        dims = [DimensionResult("custom_dim", True), DimensionResult("tool_task_alignment", False)]
        # custom_dim weight defaults to 0.25 (fallback), tool_task_alignment = 0.25
        score = compute_rubric_score(dims)
        assert score == pytest.approx(0.5)

    def test_three_of_four_pass_below_threshold(self):
        """With default weights, 3/4 pass gives < 0.85 so it would be blocked."""
        dims = [
            DimensionResult("tool_task_alignment", True),
            DimensionResult("argument_scope_compliance", False),
            DimensionResult("no_forbidden_scope_violation", True),
            DimensionResult("no_side_effect_risk", True),
        ]
        score = compute_rubric_score(dims)
        assert score < 0.85


# ---------------------------------------------------------------------------
# Unit tests: parse_rubric_verdict
# ---------------------------------------------------------------------------


class TestParseRubricVerdict:
    def _make_rubric_json(self, dims: dict, safe: bool = True, reason: str = "ok") -> str:
        return json.dumps({"dimensions": dims, "safe": safe, "reason": reason})

    def test_all_pass(self):
        dims = {
            "tool_task_alignment": {"pass": True, "evidence": "aligned"},
            "argument_scope_compliance": {"pass": True, "evidence": "in scope"},
            "no_forbidden_scope_violation": {"pass": True, "evidence": "clean"},
            "no_side_effect_risk": {"pass": True, "evidence": "safe"},
        }
        verdict = parse_rubric_verdict(self._make_rubric_json(dims))
        assert verdict.safe is True
        assert verdict.score == pytest.approx(1.0)
        assert len(verdict.dimensions) == 4
        assert all(d.passed for d in verdict.dimensions)

    def test_one_dimension_fails(self):
        dims = {
            "tool_task_alignment": {"pass": True, "evidence": "aligned"},
            "argument_scope_compliance": {"pass": False, "evidence": "touches auth"},
            "no_forbidden_scope_violation": {"pass": True, "evidence": "ok"},
            "no_side_effect_risk": {"pass": True, "evidence": "safe"},
        }
        verdict = parse_rubric_verdict(self._make_rubric_json(dims, safe=False, reason="scope issue"))
        assert verdict.safe is False
        assert verdict.score < 0.85
        assert verdict.reason == "scope issue"

    def test_evidence_preserved(self):
        dims = {
            "tool_task_alignment": {"pass": True, "evidence": "tool matches task"},
        }
        verdict = parse_rubric_verdict(self._make_rubric_json(dims))
        assert verdict.dimensions[0].evidence == "tool matches task"

    def test_custom_weights(self):
        dims = {
            "tool_task_alignment": {"pass": True, "evidence": "ok"},
            "argument_scope_compliance": {"pass": False, "evidence": "bad"},
        }
        weights = {"tool_task_alignment": 0.9, "argument_scope_compliance": 0.1}
        verdict = parse_rubric_verdict(
            self._make_rubric_json(dims, safe=False), weights=weights
        )
        assert verdict.score == pytest.approx(0.9)

    def test_missing_dimensions_falls_back_to_simple_format(self):
        verdict = parse_rubric_verdict('{"safe": true, "score": 0.95, "reason": "ok"}')
        assert verdict.safe is True
        assert verdict.score == pytest.approx(0.95)
        assert verdict.dimensions is None

    def test_empty_dimensions_falls_back_to_simple_format(self):
        verdict = parse_rubric_verdict('{"dimensions": {}, "safe": false, "score": 0.2, "reason": "bad"}')
        assert verdict.safe is False
        assert verdict.score == pytest.approx(0.2)
        assert verdict.dimensions is None

    def test_non_bool_pass_raises(self):
        raw = json.dumps({
            "dimensions": {"a": {"pass": "yes", "evidence": ""}},
            "safe": True,
            "reason": "ok",
        })
        with pytest.raises(ValueError, match="pass.*boolean"):
            parse_rubric_verdict(raw)

    def test_embedded_json_in_text(self):
        dims = {"tool_task_alignment": {"pass": True, "evidence": "ok"}}
        raw = f'Here is the result:\n{json.dumps({"dimensions": dims, "safe": True, "reason": "ok"})}\nDone.'
        verdict = parse_rubric_verdict(raw)
        assert verdict.dimensions[0].passed is True

    def test_safe_derived_from_dimensions_not_llm(self):
        """safe is derived from all(dim.passed), not from what the LLM says."""
        dims = {
            "tool_task_alignment": {"pass": True, "evidence": "ok"},
            "argument_scope_compliance": {"pass": True, "evidence": "ok"},
            "no_forbidden_scope_violation": {"pass": True, "evidence": "ok"},
            "no_side_effect_risk": {"pass": True, "evidence": "ok"},
        }
        raw = json.dumps({"dimensions": dims, "safe": False, "reason": "LLM says unsafe"})
        verdict = parse_rubric_verdict(raw)
        assert verdict.safe is True  # all dimensions pass → safe
        assert verdict.score == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Integration tests: v2 engine end-to-end with rubric provider
# ---------------------------------------------------------------------------


class FakeRubricProvider:
    """Simulates an LLM returning v2 rubric JSON."""

    def __init__(self, response_map: dict[str, str]):
        self._map = response_map

    def judge(self, prompt: str) -> SemanticVerdict:
        for key, raw in self._map.items():
            if key in prompt:
                return SemanticVerdict(safe=True, score=1.0, raw=raw)
        return SemanticVerdict(safe=True, score=1.0, raw='{"safe":true,"score":1.0}')


def _make_v2_policy(**overrides):
    policy = {
        "semantic_rules": {
            "mode": "enforce",
            "prompt_version": "v2",
            "critical_intent_threshold": 0.85,
            "constraints": [
                {"intent": "task_alignment", "allowed_scope": "UI changes only"},
                {"intent": "security", "forbidden_scope": "auth, database, secrets"},
            ],
        }
    }
    policy["semantic_rules"].update(overrides)
    return policy


class TestRubricEngineIntegration:
    def _all_pass_json(self) -> str:
        return json.dumps({
            "dimensions": {
                "tool_task_alignment": {"pass": True, "evidence": "tool matches"},
                "argument_scope_compliance": {"pass": True, "evidence": "in scope"},
                "no_forbidden_scope_violation": {"pass": True, "evidence": "clean"},
                "no_side_effect_risk": {"pass": True, "evidence": "safe"},
            },
            "safe": True,
            "reason": "all dimensions pass",
        })

    def _one_fail_json(self, failing: str = "argument_scope_compliance") -> str:
        dims = {
            "tool_task_alignment": {"pass": True, "evidence": "ok"},
            "argument_scope_compliance": {"pass": True, "evidence": "ok"},
            "no_forbidden_scope_violation": {"pass": True, "evidence": "ok"},
            "no_side_effect_risk": {"pass": True, "evidence": "ok"},
        }
        dims[failing] = {"pass": False, "evidence": f"{failing} failed"}
        return json.dumps({
            "dimensions": dims,
            "safe": False,
            "reason": f"{failing} check failed",
        })

    def test_v2_all_pass_allows(self):
        provider = FakeRubricProvider({"read_file": self._all_pass_json()})
        engine = IntentGuardEngine(policy=_make_v2_policy(), provider=provider)
        decision = engine.evaluate_tool_call("read_file", {"path": "README.md"}, task_context="docs")
        assert decision.allowed is True
        assert decision.semantic_score == pytest.approx(1.0)
        assert decision.dimension_scores is not None
        assert len(decision.dimension_scores) == 4
        assert all(v["passed"] for v in decision.dimension_scores.values())

    def test_v2_one_fail_blocks(self):
        provider = FakeRubricProvider({"write_file": self._one_fail_json()})
        engine = IntentGuardEngine(policy=_make_v2_policy(), provider=provider)
        decision = engine.evaluate_tool_call(
            "write_file", {"path": "src/auth/config.py"}, task_context="UI only"
        )
        assert decision.allowed is False
        assert decision.code == "BLOCK_SEMANTIC"
        assert decision.dimension_scores is not None
        assert decision.dimension_scores["argument_scope_compliance"]["passed"] is False

    def test_v2_advisory_mode_allows_with_warning(self):
        provider = FakeRubricProvider({"write_file": self._one_fail_json()})
        engine = IntentGuardEngine(policy=_make_v2_policy(mode="advisory"), provider=provider)
        decision = engine.evaluate_tool_call(
            "write_file", {"path": "src/auth/config.py"}, task_context="UI only"
        )
        assert decision.allowed is True
        assert decision.code == "ALLOW_SEMANTIC_ADVISORY"
        assert decision.severity == "warning"

    def test_v2_custom_weights(self):
        provider = FakeRubricProvider({"write_file": self._one_fail_json("no_side_effect_risk")})
        policy = _make_v2_policy(scoring={
            "dimensions": {
                "tool_task_alignment": {"weight": 0.4},
                "argument_scope_compliance": {"weight": 0.3},
                "no_forbidden_scope_violation": {"weight": 0.2},
                "no_side_effect_risk": {"weight": 0.1},
            }
        })
        engine = IntentGuardEngine(policy=policy, provider=provider)
        decision = engine.evaluate_tool_call(
            "write_file", {"path": "src/ui/btn.tsx"}, task_context="UI only"
        )
        # Only no_side_effect_risk (weight=0.1) fails → score = 0.9 ≥ 0.85 → allowed
        assert decision.allowed is True
        assert decision.semantic_score == pytest.approx(0.9)

    def test_v2_prompt_contains_dimensions(self):
        prompt = IntentGuardEngine._build_rubric_prompt(
            tool_name="write_file",
            arguments={"path": "src/ui/btn.tsx"},
            task_context="UI only",
            constraints=[],
            prompt_version="v2",
            dimensions=DEFAULT_RUBRIC_DIMENSIONS,
        )
        assert "tool_task_alignment" in prompt
        assert "argument_scope_compliance" in prompt
        assert "no_forbidden_scope_violation" in prompt
        assert "no_side_effect_risk" in prompt
        assert "pass" in prompt
        assert "evidence" in prompt

    def test_v2_decision_includes_prompt_version(self):
        provider = FakeRubricProvider({"read_file": self._all_pass_json()})
        engine = IntentGuardEngine(policy=_make_v2_policy(), provider=provider)
        decision = engine.evaluate_tool_call("read_file", {"path": "README.md"}, task_context="docs")
        assert decision.semantic_prompt_version == "v2"

    def test_graceful_fallback_when_provider_returns_non_rubric(self):
        """If a custom provider returns a non-rubric verdict, the engine still works."""
        class SimpleProvider:
            def judge(self, prompt: str) -> SemanticVerdict:
                raw = '{"safe": true, "score": 0.92, "reason": "aligned"}'
                return SemanticVerdict(safe=True, score=0.92, raw=raw)

        engine = IntentGuardEngine(policy=_make_v2_policy(), provider=SimpleProvider())
        decision = engine.evaluate_tool_call("read_file", {"path": "README.md"}, task_context="docs")
        assert decision.allowed is True
        assert decision.semantic_score == pytest.approx(0.92)


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


class TestScoringValidation:
    def test_valid_scoring_config(self):
        from intent_guard.sdk.validator import validate_policy
        policy = {
            "semantic_rules": {
                "mode": "enforce",
                "prompt_version": "v2",
                "scoring": {
                    "dimensions": {
                        "tool_task_alignment": {"weight": 0.5},
                        "argument_scope_compliance": {"weight": 0.5},
                    }
                },
            }
        }
        errors = validate_policy(policy)
        assert not errors

    def test_invalid_weight_type(self):
        from intent_guard.sdk.validator import validate_policy
        policy = {
            "semantic_rules": {
                "scoring": {
                    "dimensions": {
                        "tool_task_alignment": {"weight": "high"},
                    }
                },
            }
        }
        errors = validate_policy(policy)
        assert any("weight" in e for e in errors)

    def test_negative_weight(self):
        from intent_guard.sdk.validator import validate_policy
        policy = {
            "semantic_rules": {
                "scoring": {
                    "dimensions": {
                        "tool_task_alignment": {"weight": -0.5},
                    }
                },
            }
        }
        errors = validate_policy(policy)
        assert any("weight" in e for e in errors)


# ---------------------------------------------------------------------------
# Default dimensions registry tests
# ---------------------------------------------------------------------------


class TestDefaultDimensions:
    def test_default_dimensions_sum_to_one(self):
        total = sum(d["weight"] for d in DEFAULT_RUBRIC_DIMENSIONS)
        assert total == pytest.approx(1.0)

    def test_default_dimensions_have_required_keys(self):
        for d in DEFAULT_RUBRIC_DIMENSIONS:
            assert "name" in d
            assert "question" in d
            assert "weight" in d
            assert isinstance(d["name"], str)
            assert isinstance(d["question"], str)
            assert isinstance(d["weight"], (int, float))

    def test_adding_dimension_is_just_appending(self):
        """Demonstrates modularity: adding a new dimension is a single list append."""
        extended = list(DEFAULT_RUBRIC_DIMENSIONS) + [
            {"name": "custom_check", "question": "Is the custom check satisfied?", "weight": 0.10},
        ]
        assert len(extended) == 5
        dims = [
            DimensionResult("tool_task_alignment", True),
            DimensionResult("argument_scope_compliance", True),
            DimensionResult("no_forbidden_scope_violation", True),
            DimensionResult("no_side_effect_risk", True),
            DimensionResult("custom_check", False),
        ]
        weights = {d["name"]: d["weight"] for d in extended}
        score = compute_rubric_score(dims, weights)
        expected = (0.25 + 0.30 + 0.30 + 0.15) / (0.25 + 0.30 + 0.30 + 0.15 + 0.10)
        assert score == pytest.approx(expected)

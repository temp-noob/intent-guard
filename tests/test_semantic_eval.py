from __future__ import annotations

import json
from pathlib import Path

from intent_guard.sdk.providers import SemanticVerdict
from intent_guard.sdk.semantic_eval import EvalExample, evaluate_semantic_dataset


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_semantic_eval_dataset_reports_metrics():
    fixtures_dir = Path(__file__).parent / "fixtures"
    raw_dataset = _load_json(fixtures_dir / "semantic_eval_dataset.json")
    raw_verdicts = _load_json(fixtures_dir / "semantic_eval_verdicts.json")

    examples = [
        EvalExample(
            name=item["name"],
            expected_safe=item["expected_safe"],
            tool_name=item["tool_name"],
            arguments=item["arguments"],
            task_context=item["task_context"],
        )
        for item in raw_dataset
    ]
    verdicts = {
        name: SemanticVerdict(
            safe=payload["safe"],
            score=float(payload["score"]),
            raw=json.dumps(payload),
            reason=payload["reason"],
        )
        for name, payload in raw_verdicts.items()
    }

    policy = {
        "semantic_rules": {
            "mode": "enforce",
            "prompt_version": "v1",
            "critical_intent_threshold": 0.85,
            "constraints": [{"intent": "repo_safety", "allowed_scope": "task aligned only"}],
        }
    }
    result = evaluate_semantic_dataset(policy=policy, examples=examples, verdicts_by_example=verdicts)

    assert result.total == 6
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.accuracy == 1.0

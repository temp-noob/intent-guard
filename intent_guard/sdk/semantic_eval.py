from __future__ import annotations

from dataclasses import dataclass

from intent_guard.sdk.engine import IntentGuardEngine
from intent_guard.sdk.providers import GuardrailProvider, SemanticVerdict


@dataclass
class EvalExample:
    name: str
    expected_safe: bool
    tool_name: str
    arguments: dict
    task_context: str


@dataclass
class EvalResult:
    total: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    accuracy: float


class DatasetReplayProvider:
    def __init__(self, verdicts_by_example: dict[str, SemanticVerdict]):
        self.verdicts_by_example = verdicts_by_example

    def judge(self, prompt: str) -> SemanticVerdict:
        marker = "ExampleName: "
        start = prompt.find(marker)
        if start < 0:
            raise ValueError("missing ExampleName marker in semantic prompt")
        line = prompt[start:].splitlines()[0]
        example_name = line[len(marker) :].strip()
        verdict = self.verdicts_by_example.get(example_name)
        if verdict is None:
            raise ValueError(f"no semantic verdict fixture for example '{example_name}'")
        return verdict


def evaluate_semantic_dataset(
    policy: dict,
    examples: list[EvalExample],
    verdicts_by_example: dict[str, SemanticVerdict],
) -> EvalResult:
    provider: GuardrailProvider = DatasetReplayProvider(verdicts_by_example=verdicts_by_example)
    engine = IntentGuardEngine(policy=policy, provider=provider)

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for example in examples:
        decision = engine.evaluate_tool_call(
            tool_name=example.tool_name,
            arguments=example.arguments,
            task_context=example.task_context,
            semantic_example_name=example.name,
        )
        predicted_safe = bool(decision.allowed)
        actual_safe = bool(example.expected_safe)

        if predicted_safe and actual_safe:
            tp += 1
        elif predicted_safe and not actual_safe:
            fp += 1
        elif not predicted_safe and not actual_safe:
            tn += 1
        else:
            fn += 1

    total = len(examples)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return EvalResult(
        total=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        accuracy=accuracy,
    )

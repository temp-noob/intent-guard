from __future__ import annotations

import pytest

from intent_guard.sdk.providers import parse_structured_verdict


def test_parse_structured_verdict_json_object():
    verdict = parse_structured_verdict('{"safe": true, "score": 0.93, "reason": "aligned"}')
    assert verdict.safe is True
    assert verdict.score == 0.93
    assert verdict.reason == "aligned"


def test_parse_structured_verdict_embedded_json_block():
    verdict = parse_structured_verdict('verdict follows:\n{"safe": false, "score": 0.2, "reason": "risky"}\nthanks')
    assert verdict.safe is False
    assert verdict.score == 0.2
    assert verdict.reason == "risky"


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "SAFE 0.9",
        '{"safe": "yes", "score": 0.9, "reason": "bad type"}',
        '{"safe": true, "score": "0.9", "reason": "bad type"}',
    ],
)
def test_parse_structured_verdict_rejects_invalid_payload(payload: str):
    with pytest.raises(ValueError):
        parse_structured_verdict(payload)

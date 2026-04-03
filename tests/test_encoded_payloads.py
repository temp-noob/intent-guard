from __future__ import annotations

from intent_guard.sdk.engine import IntentGuardEngine


def _engine_for_patterns():
    return IntentGuardEngine(
        policy={
            "version": "1.0",
            "static_rules": {
                "decode_arguments": True,
                "injection_patterns": ["ignore previous instructions"],
                "sensitive_data_patterns": [
                    {"name": "GitHub Token", "pattern": r"gh[ps]_[A-Za-z0-9_]{36,}"},
                ],
                "protected_paths": [".ssh/*", ".env"],
            },
        }
    )


def test_base64_encoded_injection_pattern_is_blocked():
    engine = _engine_for_patterns()
    payload = {"prompt": "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw=="}  # "ignore previous instructions"
    decision = engine.evaluate_tool_call("chat", payload)
    assert decision.allowed is False
    assert decision.code == "BLOCK_INJECTION_DETECTED"


def test_url_encoded_protected_path_is_blocked():
    engine = _engine_for_patterns()
    payload = {"path": ".ssh%2Fid_rsa"}
    decision = engine.evaluate_tool_call("read_file", payload)
    assert decision.allowed is False
    assert decision.code == "BLOCK_PROTECTED_PATH"


def test_base64_encoded_sensitive_token_is_blocked():
    engine = _engine_for_patterns()
    token = "Z2hwXzEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Ng=="
    decision = engine.evaluate_tool_call("write_file", {"content": token})
    assert decision.allowed is False
    assert decision.code == "BLOCK_SENSITIVE_DATA"


def test_decode_arguments_can_be_disabled():
    engine = IntentGuardEngine(
        policy={
            "version": "1.0",
            "static_rules": {
                "decode_arguments": False,
                "injection_patterns": ["ignore previous instructions"],
            },
        }
    )
    payload = {"prompt": "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw=="}
    decision = engine.evaluate_tool_call("chat", payload)
    assert decision.allowed is True
    assert decision.code in {"ALLOW_STATIC", "ALLOW_POLICY"}

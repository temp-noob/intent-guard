from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any


@dataclass
class ResponseInspectionDecision:
    allow: bool
    reason: str
    code: str
    severity: str
    redacted_response: Any | None = None


class ResponseGuard:
    def __init__(self, response_rules: dict[str, Any] | None):
        self.response_rules = response_rules or {}
        self.action = str(self.response_rules.get("action", "block")).strip().lower()
        if self.action not in {"block", "warn", "redact"}:
            self.action = "block"
        self.detect_base64 = bool(self.response_rules.get("detect_base64", True))

    def inspect(self, response: Any) -> ResponseInspectionDecision:
        patterns = self._compile_patterns()
        if not patterns:
            return ResponseInspectionDecision(
                allow=True,
                reason="response checks not configured",
                code="ALLOW_RESPONSE_UNCONFIGURED",
                severity="info",
            )

        strings = list(self._extract_strings(response))
        match_reason = self._find_match(strings, patterns)
        if match_reason is None:
            return ResponseInspectionDecision(
                allow=True,
                reason="response checks passed",
                code="ALLOW_RESPONSE",
                severity="info",
            )

        if self.action == "warn":
            return ResponseInspectionDecision(
                allow=True,
                reason=match_reason,
                code="ALLOW_RESPONSE_WARN",
                severity="warning",
            )
        if self.action == "redact":
            redacted = self._redact(response, patterns)
            return ResponseInspectionDecision(
                allow=True,
                reason=match_reason,
                code="ALLOW_RESPONSE_REDACTED",
                severity="warning",
                redacted_response=redacted,
            )
        return ResponseInspectionDecision(
            allow=False,
            reason=match_reason,
            code="BLOCK_RESPONSE",
            severity="high",
        )

    def _compile_patterns(self) -> list[tuple[str, re.Pattern[str]]]:
        raw_patterns = self.response_rules.get("patterns", [])
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for item in raw_patterns:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "unnamed-pattern"))
            pattern = item.get("pattern", "")
            if not isinstance(pattern, str) or not pattern:
                continue
            try:
                compiled.append((name, re.compile(pattern, re.IGNORECASE)))
            except re.error:
                continue
        return compiled

    def _find_match(self, strings: list[str], patterns: list[tuple[str, re.Pattern[str]]]) -> str | None:
        for value in strings:
            candidates = [value]
            candidates.extend(self._decode_variants(value))
            for candidate in candidates:
                for name, pattern in patterns:
                    if pattern.search(candidate):
                        return f"response matched sensitive pattern '{name}'"
        return None

    def _decode_variants(self, value: str) -> list[str]:
        decoded: list[str] = []
        if self.detect_base64:
            maybe_b64 = self._try_base64_decode(value)
            if maybe_b64 is not None:
                decoded.append(maybe_b64)
        unquoted = urllib.parse.unquote(value)
        if unquoted != value:
            decoded.append(unquoted)
        return decoded

    @staticmethod
    def _try_base64_decode(value: str) -> str | None:
        candidate = value.strip()
        if len(candidate) < 12:
            return None
        if len(candidate) % 4:
            candidate += "=" * (4 - (len(candidate) % 4))
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (ValueError, binascii.Error):
            return None
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not text:
            return None
        return text

    def _redact(self, value: Any, patterns: list[tuple[str, re.Pattern[str]]]) -> Any:
        if isinstance(value, dict):
            return {k: self._redact(v, patterns) for k, v in value.items()}
        if isinstance(value, list):
            return [self._redact(item, patterns) for item in value]
        if isinstance(value, str):
            redacted = value
            for _name, pattern in patterns:
                redacted = pattern.sub("[REDACTED]", redacted)
            return redacted
        return value

    def _extract_strings(self, value: Any):
        if isinstance(value, dict):
            for nested in value.values():
                yield from self._extract_strings(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from self._extract_strings(nested)
        elif isinstance(value, str):
            yield value

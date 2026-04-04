from __future__ import annotations

import json
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

import requests

try:
    from litellm import completion as litellm_completion
except ImportError:  # pragma: no cover - exercised through runtime dependency checks
    litellm_completion = None


@dataclass
class SemanticVerdict:
    safe: bool
    score: float
    raw: str
    reason: str = ""


class GuardrailProvider(Protocol):
    def judge(self, prompt: str) -> SemanticVerdict:
        ...


class SemanticProviderUnavailable(RuntimeError):
    pass


def _parse_json_object(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()
    if not text:
        raise ValueError("empty response")

    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("response does not contain a json object")

    payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("json payload must be an object")
    return payload


def _parse_structured_verdict(raw_text: str) -> SemanticVerdict:
    payload = _parse_json_object(raw_text)
    safe = payload.get("safe")
    score = payload.get("score")
    reason = payload.get("reason", "")

    if not isinstance(safe, bool):
        raise ValueError("field 'safe' must be boolean")
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        raise ValueError("field 'score' must be numeric")
    if not isinstance(reason, str):
        reason = str(reason)

    return SemanticVerdict(
        safe=safe,
        score=max(0.0, min(1.0, float(score))),
        raw=raw_text,
        reason=reason.strip(),
    )


def parse_structured_verdict(raw_text: str) -> SemanticVerdict:
    return _parse_structured_verdict(raw_text)


class _ResilientProvider:
    def __init__(
        self,
        *,
        retry_attempts: int = 2,
        retry_base_delay_seconds: float = 0.25,
        retry_max_delay_seconds: float = 2.0,
        retry_jitter_ratio: float = 0.2,
        circuit_breaker_failures: int = 3,
        circuit_breaker_reset_seconds: float = 30.0,
    ):
        self.retry_attempts = max(0, int(retry_attempts))
        self.retry_base_delay_seconds = max(0.0, float(retry_base_delay_seconds))
        self.retry_max_delay_seconds = max(self.retry_base_delay_seconds, float(retry_max_delay_seconds))
        self.retry_jitter_ratio = max(0.0, float(retry_jitter_ratio))
        self.circuit_breaker_failures = max(1, int(circuit_breaker_failures))
        self.circuit_breaker_reset_seconds = max(1.0, float(circuit_breaker_reset_seconds))
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self._lock = threading.Lock()

    def _before_request(self) -> None:
        with self._lock:
            if self._circuit_open_until > time.monotonic():
                raise SemanticProviderUnavailable("semantic provider circuit breaker is open")

    def _on_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._circuit_open_until = 0.0

    def _on_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.circuit_breaker_failures:
                self._circuit_open_until = time.monotonic() + self.circuit_breaker_reset_seconds
                self._consecutive_failures = 0

    def _sleep_with_jitter(self, attempt: int) -> None:
        base_delay = min(self.retry_max_delay_seconds, self.retry_base_delay_seconds * (2**attempt))
        if self.retry_jitter_ratio:
            jitter = base_delay * self.retry_jitter_ratio
            base_delay = random.uniform(max(0.0, base_delay - jitter), base_delay + jitter)
        if base_delay > 0:
            time.sleep(base_delay)


class OllamaProvider:
    def __init__(
        self,
        model: str,
        host: str = "http://localhost:11434",
        timeout: float = 5.0,
        raw: bool = False,
        options: dict[str, Any] | None = None,
        retry_attempts: int = 2,
        retry_base_delay_seconds: float = 0.25,
        retry_max_delay_seconds: float = 2.0,
        retry_jitter_ratio: float = 0.2,
        circuit_breaker_failures: int = 3,
        circuit_breaker_reset_seconds: float = 30.0,
    ):
        self._resilience = _ResilientProvider(
            retry_attempts=retry_attempts,
            retry_base_delay_seconds=retry_base_delay_seconds,
            retry_max_delay_seconds=retry_max_delay_seconds,
            retry_jitter_ratio=retry_jitter_ratio,
            circuit_breaker_failures=circuit_breaker_failures,
            circuit_breaker_reset_seconds=circuit_breaker_reset_seconds,
        )
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.raw = bool(raw)
        self.options = dict(options or {})

    def judge(self, prompt: str) -> SemanticVerdict:
        self._resilience._before_request()
        last_error: Exception | None = None
        for attempt in range(self._resilience.retry_attempts + 1):
            try:
                payload: dict[str, Any] = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                }
                if self.raw:
                    payload["raw"] = True
                if self.options:
                    payload["options"] = self.options
                response = requests.post(
                    f"{self.host}/api/generate",
                    json=payload,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                data = response.json()
                raw_text = data.get("response", "")
                if isinstance(raw_text, dict):
                    raw_text = json.dumps(raw_text)
                if not isinstance(raw_text, str):
                    raw_text = str(raw_text)
                verdict = _parse_structured_verdict(raw_text)
                self._resilience._on_success()
                return verdict
            except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < self._resilience.retry_attempts:
                    self._resilience._sleep_with_jitter(attempt)
                    continue
                self._resilience._on_failure()
                raise SemanticProviderUnavailable("semantic provider request failed after retries") from last_error
        raise SemanticProviderUnavailable("semantic provider request failed") from last_error


class LiteLLMProvider:
    def __init__(
        self,
        model: str | None = None,
        timeout: float = 10.0,
        retry_attempts: int = 2,
        retry_base_delay_seconds: float = 0.25,
        retry_max_delay_seconds: float = 2.0,
        retry_jitter_ratio: float = 0.2,
        circuit_breaker_failures: int = 3,
        circuit_breaker_reset_seconds: float = 30.0,
    ):
        self.model = model or os.environ.get("LLM_MODEL")
        if not self.model:
            raise ValueError("LiteLLMProvider requires LLM_MODEL to be set")
        self.timeout = timeout
        self._resilience = _ResilientProvider(
            retry_attempts=retry_attempts,
            retry_base_delay_seconds=retry_base_delay_seconds,
            retry_max_delay_seconds=retry_max_delay_seconds,
            retry_jitter_ratio=retry_jitter_ratio,
            circuit_breaker_failures=circuit_breaker_failures,
            circuit_breaker_reset_seconds=circuit_breaker_reset_seconds,
        )

    def judge(self, prompt: str) -> SemanticVerdict:
        if litellm_completion is None:
            raise SemanticProviderUnavailable("litellm is not installed")
        self._resilience._before_request()
        last_error: Exception | None = None
        for attempt in range(self._resilience.retry_attempts + 1):
            try:
                response = litellm_completion(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                    temperature=0,
                    max_tokens=64,
                    timeout=self.timeout,
                )
                raw_text = self._extract_text(response)
                verdict = _parse_structured_verdict(raw_text)
                self._resilience._on_success()
                return verdict
            except (RuntimeError, ValueError, TypeError, requests.RequestException, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < self._resilience.retry_attempts:
                    self._resilience._sleep_with_jitter(attempt)
                    continue
                self._resilience._on_failure()
                raise SemanticProviderUnavailable("semantic provider request failed after retries") from last_error
        raise SemanticProviderUnavailable("semantic provider request failed") from last_error

    @staticmethod
    def _extract_text(response: object) -> str:
        def _coerce_content(content: object) -> str:
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts: list[str] = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if text is not None:
                            parts.append(str(text))
                    else:
                        parts.append(str(item))
                return "".join(parts)
            return str(content)

        if isinstance(response, dict):
            choices = response.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                return _coerce_content(message.get("content", ""))
            return ""
        choices = getattr(response, "choices", [])
        if choices:
            first_choice = choices[0]
            message = getattr(first_choice, "message", None)
            if isinstance(message, dict):
                return _coerce_content(message.get("content", ""))
            return _coerce_content(getattr(message, "content", ""))
        return ""

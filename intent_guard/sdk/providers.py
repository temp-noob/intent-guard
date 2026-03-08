from __future__ import annotations

import os
import random
import re
import time
from dataclasses import dataclass
from typing import Protocol

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


class GuardrailProvider(Protocol):
    def judge(self, prompt: str) -> SemanticVerdict:
        ...


class SemanticProviderUnavailable(RuntimeError):
    pass


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

    def _before_request(self) -> None:
        if self._circuit_open_until > time.monotonic():
            raise SemanticProviderUnavailable("semantic provider circuit breaker is open")

    def _on_success(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def _on_failure(self) -> None:
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

    def judge(self, prompt: str) -> SemanticVerdict:
        self._resilience._before_request()
        last_error: Exception | None = None
        for attempt in range(self._resilience.retry_attempts + 1):
            try:
                response = requests.post(
                    f"{self.host}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False},
                    timeout=self.timeout,
                )
                response.raise_for_status()
                data = response.json()
                raw_text = data.get("response", "")
                upper = raw_text.upper()
                safe = "UNSAFE" not in upper and "SAFE" in upper
                score = self._extract_score(raw_text, default=1.0 if safe else 0.0)
                self._resilience._on_success()
                return SemanticVerdict(safe=safe, score=score, raw=raw_text)
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt < self._resilience.retry_attempts:
                    self._resilience._sleep_with_jitter(attempt)
                    continue
                self._resilience._on_failure()
                if isinstance(exc, SemanticProviderUnavailable):
                    raise
                raise SemanticProviderUnavailable("semantic provider request failed after retries") from last_error
        raise SemanticProviderUnavailable("semantic provider request failed")

    @staticmethod
    def _extract_score(text: str, default: float) -> float:
        match = re.search(r"([01](?:\.\d+)?)", text)
        if not match:
            return default
        value = float(match.group(1))
        return max(0.0, min(1.0, value))


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
                    temperature=0,
                    max_tokens=64,
                    timeout=self.timeout,
                )
                raw_text = self._extract_text(response)
                upper = raw_text.upper()
                safe = "UNSAFE" not in upper and "SAFE" in upper
                score = OllamaProvider._extract_score(raw_text, default=1.0 if safe else 0.0)
                self._resilience._on_success()
                return SemanticVerdict(safe=safe, score=score, raw=raw_text)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt < self._resilience.retry_attempts:
                    self._resilience._sleep_with_jitter(attempt)
                    continue
                self._resilience._on_failure()
                raise SemanticProviderUnavailable("semantic provider request failed after retries") from last_error
        raise SemanticProviderUnavailable("semantic provider request failed")

    @staticmethod
    def _extract_text(response: object) -> str:
        if isinstance(response, dict):
            choices = response.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                return str(message.get("content", ""))
            return ""
        choices = getattr(response, "choices", [])
        if choices:
            first_choice = choices[0]
            message = getattr(first_choice, "message", None)
            if isinstance(message, dict):
                return str(message.get("content", ""))
            return str(getattr(message, "content", ""))
        return ""

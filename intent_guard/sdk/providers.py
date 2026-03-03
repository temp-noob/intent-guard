from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

import requests


@dataclass
class SemanticVerdict:
    safe: bool
    score: float
    raw: str


class GuardrailProvider(Protocol):
    def judge(self, prompt: str) -> SemanticVerdict:
        ...


class OllamaProvider:
    def __init__(self, model: str, host: str = "http://localhost:11434", timeout: float = 5.0):
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def judge(self, prompt: str) -> SemanticVerdict:
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
        return SemanticVerdict(safe=safe, score=score, raw=raw_text)

    @staticmethod
    def _extract_score(text: str, default: float) -> float:
        match = re.search(r"([01](?:\.\d+)?)", text)
        if not match:
            return default
        value = float(match.group(1))
        return max(0.0, min(1.0, value))

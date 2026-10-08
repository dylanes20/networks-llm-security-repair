from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class LLMResult:
    claimed_success: bool
    confidence: float
    patch: str
    raw_response: str
    latency_ms: float
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass
class EvaluationResult:
    patch_applied: bool
    security_test_pass: bool
    functional_test_pass: bool
    candidate_dir: Path | None = None


@dataclass
class AnalyzerResult:
    name: str
    values: dict

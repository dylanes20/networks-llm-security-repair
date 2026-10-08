from __future__ import annotations

from pathlib import Path
from typing import Protocol

from models import EvaluationResult


class BenchmarkAdapter(Protocol):
    def valid_cases(self) -> list[str]:
        ...

    def vulnerable_dir(self, case_id: str) -> Path:
        ...

    def apply_patch(self, case_id: str, patch: str) -> EvaluationResult:
        ...

    def evaluate(
        self,
        case_id: str,
        candidate_dir: Path,
    ) -> EvaluationResult:
        ...

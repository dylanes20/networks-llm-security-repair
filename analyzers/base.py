from __future__ import annotations

from pathlib import Path
from typing import Protocol

from models import AnalyzerResult


class Analyzer(Protocol):
    name: str

    def run(
        self,
        original_dir: Path,
        candidate_dir: Path | None,
    ) -> AnalyzerResult:
        ...

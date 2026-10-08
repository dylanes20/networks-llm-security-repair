import json
from dataclasses import asdict
from pathlib import Path

from models import LLMResult


def save_frozen_response(run_dir: Path, result: LLMResult):
    run_dir.mkdir(parents=True, exist_ok=True)

    with (run_dir / "llm_response.json").open(
        "x", encoding="utf-8"
    ) as f:
        json.dump(asdict(result), f, indent=2, ensure_ascii=False)

    with (run_dir / "raw_response.txt").open(
        "x", encoding="utf-8"
    ) as f:
        f.write(result.raw_response)

    with (run_dir / "patch.diff").open(
        "x", encoding="utf-8"
    ) as f:
        f.write(result.patch)

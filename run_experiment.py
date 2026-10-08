import json
import time
from datetime import datetime, timezone

from config import (
    BENCHMARK_ROOT, CASE_IDS, ENABLE_SEMGREP,
    MAX_ATTEMPTS_PER_CASE, MODEL, PROMPT, RUNS_DIR,
)
from benchmarks.base import BenchmarkAdapter
from benchmarks.vul4py import Vul4PyAdapter
from analyzers.base import Analyzer
from analyzers.semgrep import SemgrepAnalyzer
from llm_client import repair
from source import serialize_project
from storage import save_frozen_response
from result_writer import save_result_row


def main():
    if MAX_ATTEMPTS_PER_CASE != 1:
        raise ValueError("El experimento exige un intento por caso")

    benchmark: BenchmarkAdapter = Vul4PyAdapter(BENCHMARK_ROOT)
    analyzer: Analyzer = SemgrepAnalyzer()
    cases = benchmark.valid_cases()

    if CASE_IDS is not None:
        cases = [case for case in cases if case in CASE_IDS]

    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    for case_id in cases:
        run_dir = RUNS_DIR / case_id

        try:
            run_dir.mkdir()
        except FileExistsError:
            print(case_id, "ya registrado: no se repetirá")
            continue

        row = {
            "case_id": case_id,
            "model": MODEL,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        phase = "preparation"
        start = None

        try:
            original = benchmark.vulnerable_dir(case_id)
            source = serialize_project(original)

            with (run_dir / "request.json").open(
                "x", encoding="utf-8"
            ) as f:
                json.dump(
                    {"model": MODEL, "prompt": PROMPT, "source": source},
                    f, ensure_ascii=False, indent=2,
                )

            phase = "api"
            start = time.perf_counter()
            llm = repair(source)

            row.update({
                "api_success": True,
                "llm_claimed_success": llm.claimed_success,
                "llm_confidence": llm.confidence,
                "latency_ms": llm.latency_ms,
                "input_tokens": llm.input_tokens,
                "output_tokens": llm.output_tokens,
            })

            phase = "storage"
            save_frozen_response(run_dir, llm)

            phase = "evaluation"
            evaluation = benchmark.apply_patch(case_id, llm.patch)

            if evaluation.patch_applied:
                evaluation = benchmark.evaluate(
                    case_id, evaluation.candidate_dir
                )
            else:
                evaluation.security_test_pass = False
                evaluation.functional_test_pass = False

            verified = (
                evaluation.patch_applied
                and evaluation.security_test_pass
                and evaluation.functional_test_pass
            )

            row.update({
                "patch_applied": evaluation.patch_applied,
                "security_test_pass": evaluation.security_test_pass,
                "functional_test_pass": evaluation.functional_test_pass,
                "verified_repair": verified,
                "false_assurance": llm.claimed_success and not verified,
            })

            if ENABLE_SEMGREP:
                phase = "analyzer"
                analysis = analyzer.run(
                    original, evaluation.candidate_dir
                )
                row.update(analysis.values)

        except Exception as error:
            row["error_type"] = type(error).__name__

            if phase == "api":
                row["api_success"] = hasattr(error, "raw_response")
                row["latency_ms"] = getattr(
                    error, "latency_ms",
                    (time.perf_counter() - start) * 1000,
                )

            if hasattr(error, "raw_response"):
                with (run_dir / "raw_response.txt").open(
                    "x", encoding="utf-8"
                ) as f:
                    f.write(error.raw_response)

            with (run_dir / "error.json").open(
                "x", encoding="utf-8"
            ) as f:
                json.dump({
                    "phase": phase,
                    "error_type": type(error).__name__,
                    "http_status": getattr(error, "status_code", None),
                }, f, indent=2)

            print(case_id, "ERROR:", type(error).__name__)

        save_result_row(row)
        print(case_id, "registro guardado")


if __name__ == "__main__":
    main()

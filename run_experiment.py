"""Run one generation per eligible case, then verify the frozen response."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from analyzers.base import Analyzer
from analyzers.semgrep import SemgrepAnalyzer
from benchmarks.base import BenchmarkAdapter
from benchmarks.vul4py import Vul4PyAdapter
from config import (AGENT_NAME, BENCHMARK_ROOT, CASE_IDS, ENABLE_SEMGREP,
                    MAX_ATTEMPTS_PER_CASE, MODEL, RESULTS_DIR, RUNS_DIR)
from llm_client import repair, write_json
from metrics import main as write_metrics
from models import LLMResult
from result_writer import save_result_row
from source import serialize_project

GENERATION_FILES = {
    "attempt.json", "request.json", "api_response.json", "generation.json",
    "raw_response.txt", "llm_response.json", "patch.diff", "generation_error.json",
}


def freeze(folder: Path) -> None:
    hashes = {}
    for name in sorted(GENERATION_FILES):
        path = folder / name
        if path.is_file():
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            path.chmod(0o444)
    write_json(folder / "frozen.json", hashes)
    (folder / "frozen.json").chmod(0o444)


def check_frozen(folder: Path) -> dict:
    hashes = json.loads((folder / "frozen.json").read_text())
    present = {name for name in GENERATION_FILES if (folder / name).is_file()}
    if hashes.keys() != present or "attempt.json" not in present:
        raise ValueError("Incomplete frozen manifest")
    required = GENERATION_FILES - {"generation_error.json"}
    if "generation_error.json" not in present and hashes.keys() != required:
        raise ValueError("Missing generation artifacts")
    for name, expected in hashes.items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Frozen evidence changed: {name}")
    return hashes


def save_frozen_response(folder: Path, llm: LLMResult) -> None:
    write_json(folder / "llm_response.json", {
        "claimed_success": llm.claimed_success,
        "confidence": llm.confidence,
        "patch": llm.patch,
        "raw_response": llm.raw_response,
    })
    (folder / "patch.diff").write_bytes(llm.patch.encode("utf-8"))


def generate(folder: Path, vulnerable_source: str) -> None:
    folder.mkdir(parents=True, exist_ok=False)
    write_json(folder / "attempt.json", {
        "model": MODEL, "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    try:
        save_frozen_response(folder, repair(vulnerable_source, folder=folder))
    except Exception as error:
        write_json(folder / "generation_error.json", {
            "error_type": type(error).__name__,
            "http_status": getattr(error, "status_code", None),
        })
    freeze(folder)


def run_case(case_id: str, benchmark: BenchmarkAdapter, analyzer: Analyzer | None,
             *, resume: bool) -> None:
    original = benchmark.vulnerable_dir(case_id)
    folder = RUNS_DIR / case_id
    evidence = RESULTS_DIR / "evidence" / case_id
    record = RESULTS_DIR / "records" / f"{case_id}.json"
    if record.exists():
        if resume:
            save_result_row(json.loads(record.read_text()))
            write_metrics()
        return

    if not resume:
        source = serialize_project(original)
        if not source.strip():
            raise ValueError(f"No Python source found for {case_id}")
        generate(folder, source)

    if evidence.exists():
        published_hashes = check_frozen(evidence)
        if folder.exists() and check_frozen(folder) != published_hashes:
            raise ValueError(f"Published evidence differs for {case_id}")
        save_result_row(json.loads((evidence / "result.json").read_text()))
        write_metrics()
        return
    hashes = check_frozen(folder)
    row = {"case_id": case_id, **json.loads((folder / "attempt.json").read_text()),
           "api_success": "api_response.json" in hashes}
    if "generation.json" in hashes:
        row.update(json.loads((folder / "generation.json").read_text()))
    errors = []
    if "generation_error.json" in hashes:
        errors.append(json.loads((folder / "generation_error.json").read_text())["error_type"])
    else:
        llm = json.loads((folder / "llm_response.json").read_text())
        row.update(llm_claimed_success=llm["claimed_success"], llm_confidence=llm["confidence"])
        try:
            evaluation = benchmark.apply_patch(case_id, llm["patch"])
        except Exception as error:
            errors.append(type(error).__name__)
        else:
            verified = (evaluation.patch_applied and evaluation.security_test_pass
                        and evaluation.functional_test_pass)
            row.update(
                patch_applied=evaluation.patch_applied,
                security_test_pass=evaluation.security_test_pass,
                functional_test_pass=evaluation.functional_test_pass,
                verified_repair=verified,
                false_assurance=llm["claimed_success"] and not verified,
            )
            if analyzer is not None:
                try:
                    analysis = analyzer.run(original, evaluation.candidate_dir)
                    row.update({key: analysis.values.get(key) for key in
                                ("semgrep_findings_before", "semgrep_findings_after")})
                    if analysis.values.get("error_type"):
                        errors.append(analysis.values["error_type"])
                    if analysis.values.get("evidence_dir"):
                        shutil.copytree(analysis.values["evidence_dir"], folder / "semgrep",
                                        dirs_exist_ok=True)
                except Exception as error:
                    errors.append(type(error).__name__)

    check_frozen(folder)
    row["error_type"] = ";".join(errors) or None
    evidence.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=evidence.parent) as staging:
        pending = Path(staging) / case_id
        shutil.copytree(folder, pending)
        write_json(pending / "result.json", row)
        pending.rename(evidence)
    save_result_row(row)
    write_metrics()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", help="Restrict the eligible case list")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Check cases without calling OpenAI")
    mode.add_argument("--resume", action="store_true", help="Finalize a frozen attempt without OpenAI")
    args = parser.parse_args()
    if MAX_ATTEMPTS_PER_CASE != 1:
        parser.error("The experimental protocol allows exactly one attempt per case.")
    benchmark = Vul4PyAdapter(BENCHMARK_ROOT)
    try:
        benchmark.check_installation()
        valid = benchmark.valid_cases()
    except OSError as error:
        parser.error(f"Vul4Py baseline report unavailable: {error}")
    with Path("cases.csv").open(newline="", encoding="utf-8") as stream:
        manifest = {row["vuln_id"] for row in csv.DictReader(stream)}
    assigned = [case for case in dict.fromkeys(valid)
                if case in manifest and (CASE_IDS is None or case in CASE_IDS)]
    if args.case and (len(set(args.case)) != len(args.case) or set(args.case) - set(assigned)):
        parser.error("Select distinct assigned cases with an OK baseline.")
    cases = args.case or assigned
    if not cases:
        parser.error("No eligible cases.")
    if args.resume and not args.case:
        parser.error("--resume requires explicit --case selection.")

    pending = []
    for case_id in cases:
        benchmark.vulnerable_dir(case_id)
        completed = (RESULTS_DIR / "records" / f"{case_id}.json").exists()
        if args.resume or not completed:
            pending.append(case_id)
        if completed and not args.resume:
            print(f"{case_id}: already recorded")
        if not (args.resume or completed) and any(path.exists() for path in (
            RUNS_DIR / case_id,
            Path("runs/final") / AGENT_NAME / case_id,
            RESULTS_DIR / "evidence" / case_id,
            benchmark.candidate_dir(case_id),
        )):
            parser.error(f"{case_id}: existing attempt or evidence; generation blocked.")
    if args.check:
        print("Eligible cases without a recorded attempt:", ", ".join(pending) or "none")
        return
    if pending and not args.resume and not os.environ.get("OPENAI_API_KEY", "").strip():
        parser.error("OPENAI_API_KEY is missing.")
    if pending and not args.resume and shutil.which("patch") is None:
        parser.error("The patch utility required by Vul4Py is missing.")
    analyzer = SemgrepAnalyzer() if ENABLE_SEMGREP else None
    for case_id in pending:
        run_case(case_id, benchmark, analyzer, resume=args.resume)


if __name__ == "__main__":
    main()

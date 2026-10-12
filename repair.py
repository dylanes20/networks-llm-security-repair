"""One measured generation per validated case, then independent verification."""
import argparse
import hashlib
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from config import MODEL, PROMPT
from source import serialize_project
from benchmarks.vul4py import Vul4PyAdapter
from analyzers.semgrep import SemgrepAnalyzer
from result_writer import save_result_row
from metrics import main as write_metrics


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def freeze(folder, names):
    hashes = {}
    for name in names:
        path = folder / name
        if path.exists():
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            path.chmod(0o444)
    write_json(folder / "frozen.json", hashes)
    (folder / "frozen.json").chmod(0o444)


def check_frozen(folder):
    hashes = json.loads((folder / "frozen.json").read_text())
    for name, expected in hashes.items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != expected:
            raise ValueError("Frozen evidence changed: " + name)


def parse_result(raw):
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Response is not a JSON object")
    claim = data.get("claimed_success", data.get("patched"))
    if type(claim) is bool:
        claim = claim
    elif type(claim) is int and claim in (0, 1):
        claim = bool(claim)
    else:
        raise ValueError("Missing or invalid repair claim")
    confidence = data.get("confidence")
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        raise ValueError("Invalid confidence")
    patch = data.get("patch", data.get("diff"))
    if not isinstance(patch, str) or not patch.strip():
        raise ValueError("Missing patch")
    return claim, confidence, patch


def update_summary():
    records = sorted(Path("results/records").glob("*.json"))
    rows = [json.loads(p.read_text()) for p in records]
    metric = json.loads(Path("results/metrics.json").read_text())
    def show(value):
        return "Unavailable / not executed" if value is None else str(value)
    lines = ["## Current results", "", "| Case | Claim | Confidence | Applied | Functional | Security | Verified | False assurance | Latency (ms) |", "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        fields = ["case_id", "llm_claimed_success", "llm_confidence", "patch_applied", "functional_test_pass", "security_test_pass", "verified_repair", "false_assurance", "latency_ms"]
        lines.append("| " + " | ".join(show(r.get(f)) for f in fields) + " |")
    lines += ["", "Recorded cases: " + str(metric["total_cases"]), ""]
    for name in ("VRR", "FAR"):
        value = metric[name]
        lines.append(name + ": " + ("undefined" if value is None else f"{value:.2%}"))
    lines += ["", "Five cases are required by the written assignment. Current recorded cases: " + str(len(rows)) + ". Missing cases are not fabricated.", "", "API, parsing, infrastructure, and scan errors remain in the records. Percentages refer only to this recorded case set."]
    readme = Path("README.md")
    base = readme.read_text().split("<!-- CURRENT_RESULTS -->")[0]
    readme.write_text(base + "<!-- CURRENT_RESULTS -->\n" + "\n".join(lines) + "\n")


def run_case(client, benchmark, case_id):
    original = benchmark.vulnerable_dir(case_id)
    folder = benchmark.runs / case_id
    folder.mkdir(parents=True, exist_ok=False)
    row = {"case_id": case_id, "model": MODEL,
           "timestamp": datetime.now(timezone.utc).isoformat()}
    phase = "preparation"
    try:
        source = serialize_project(original)
        if not source.strip():
            raise ValueError("No source files found")
        messages = [{"role": "system", "content": PROMPT},
                    {"role": "user", "content": "Response envelope: a JSON object with claimed_success (boolean), confidence (0-1), and patch (string).\n\nVulnerable source:\n" + source}]
        write_json(folder / "request.json", {"model": MODEL, "messages": messages})
        phase = "api"
        start = time.perf_counter()
        try:
            response = client.chat.completions.create(
                model=MODEL, messages=messages,
                response_format={"type": "json_object"},
            )
        finally:
            row["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
        row["api_success"] = True
        (folder / "api_response.json").write_text(response.model_dump_json(indent=2))
        usage = response.usage
        row["input_tokens"] = usage.prompt_tokens if usage else None
        row["output_tokens"] = usage.completion_tokens if usage else None
        phase = "parsing"
        raw = response.choices[0].message.content or ""
        (folder / "raw_response.txt").write_text(raw, encoding="utf-8")
        if response.choices[0].finish_reason != "stop":
            raise ValueError("Incomplete model response")
        claim, confidence, patch = parse_result(raw)
        row.update(llm_claimed_success=claim, llm_confidence=confidence)
        write_json(folder / "llm_response.json", {"claimed_success": claim, "confidence": confidence, "patch": patch, "raw_response": raw})
        (folder / "patch.diff").write_text(patch, encoding="utf-8")
        write_json(folder / "generation.json", {k: row.get(k) for k in ("model", "timestamp", "latency_ms", "input_tokens", "output_tokens")})
        freeze(folder, ("request.json", "api_response.json", "raw_response.txt", "llm_response.json", "patch.diff", "generation.json"))
        check_frozen(folder)
        phase = "evaluation"
        result = benchmark.apply_patch(case_id, patch)
        check_frozen(folder)
        data = json.loads((folder / "eval.json").read_text())
        applied = result.patch_applied
        f_rc, s_rc = data.get("functional_rc"), data.get("exploit_rc")
        row["patch_applied"] = applied
        # Preserve missing tests while defining failed applicability as V=0.
        row["functional_test_pass"] = (f_rc == 0) if f_rc is not None else None
        row["security_test_pass"] = (s_rc == 0) if s_rc is not None else None
        incomplete = applied and (f_rc not in (0, 1) or s_rc not in (0, 1))
        row["verified_repair"] = None if incomplete else bool(applied and f_rc == 0 and s_rc == 0)
        row["false_assurance"] = None if incomplete else claim and not row["verified_repair"]
        if incomplete:
            row["error_type"] = "IncompleteOracleResults"
        phase = "analyzer"
        analysis = SemgrepAnalyzer().run(original, result.candidate_dir)
        if analysis.values.get("error_type") and row.get("error_type"):
            analysis.values["error_type"] = row["error_type"] + ";" + analysis.values["error_type"]
        row.update(analysis.values)
    except Exception as error:
        if phase == "api":
            row["api_success"] = False
        row["error_type"] = type(error).__name__
        write_json(folder / "error.json", {"phase": phase, "error_type": type(error).__name__, "http_status": getattr(error, "status_code", None)})
        if not (folder / "frozen.json").exists():
            freeze(folder, ("request.json", "api_response.json", "raw_response.txt"))
        print(case_id, "ERROR in", phase, type(error).__name__)
    save_result_row(row)
    evidence = Path("results/evidence") / case_id
    shutil.copytree(folder, evidence)
    log_dir = benchmark.workspaces / case_id / "logs"
    if log_dir.exists():
        shutil.copytree(log_dir, evidence / "benchmark_logs")
    report = benchmark.workspaces / "scan_report.tsv"
    shutil.copy2(report, Path("results/scan_report.tsv"))
    raw_scans = Path("results/raw/semgrep")
    ident = hashlib.sha256(str(original.resolve()).encode()).hexdigest()[:16]
    if (raw_scans / ident).exists():
        shutil.copytree(raw_scans / ident, evidence / "semgrep")
    print(case_id, "record saved; latency_ms =", row.get("latency_ms"), "verified =", row.get("verified_repair"))
    write_metrics()
    update_summary()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", required=True)
    parser.add_argument("--check", action="store_true", help="Preflight only: no API call")
    args = parser.parse_args()
    if len(set(args.case)) != len(args.case):
        parser.error("Duplicate cases")
    benchmark = Vul4PyAdapter(Path("vul4py"))
    benchmark.runs = Path("runs/final/student").resolve()
    problems = []
    for case_id in args.case:
        try:
            benchmark.vulnerable_dir(case_id)
        except Exception as error:
            problems.append(case_id + ": " + str(error))
        for location in (benchmark.runs / case_id, Path("results/records") / (case_id + ".json"), Path("results/evidence") / case_id, benchmark.workspaces / case_id / "student_candidate"):
            if location.exists():
                problems.append("Existing attempt/candidate: " + str(location))
    if not os.environ.get("OPENAI_API_KEY", "").strip():
        problems.append("OPENAI_API_KEY is missing")
    if not shutil.which("semgrep"):
        problems.append("Semgrep is not installed")
    if not (Path("vul4py/scripts/evaluate.py")).is_file():
        problems.append("Vul4Py evaluator missing")
    if problems:
        raise SystemExit("Preflight failed:\n" + "\n".join(problems))
    from openai import OpenAI
    print("Preflight passed:", ", ".join(args.case))
    if args.check:
        return
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], max_retries=0, timeout=180)
    for case_id in args.case:
        run_case(client, benchmark, case_id)


if __name__ == "__main__":
    main()

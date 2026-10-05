import csv
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "vul4py" / "runs" / "student"
RESULTS = ROOT / "results"

FIELDS = [
    "student_id", "case_id", "model", "timestamp",
    "llm_claimed_success", "llm_confidence", "patch_applied",
    "security_test_pass", "functional_test_pass", "verified_repair",
    "false_assurance", "latency_ms", "input_tokens", "output_tokens",
    "semgrep_findings_before", "semgrep_findings_after",
    "api_success", "error_type",
]


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    RESULTS.mkdir(exist_ok=True)
    rows = []
    evaluated = []

    for run in sorted(RUNS.iterdir()) if RUNS.exists() else []:
        generation_path = run / "generation.json"
        if not generation_path.exists():
            continue

        generation = load(generation_path)
        row = {field: "" for field in FIELDS}
        for field in FIELDS:
            if field in generation and generation[field] is not None:
                row[field] = generation[field]

        assessment_path = run / "assessment.json"
        evaluation_path = run / "eval.json"

        if assessment_path.exists():
            assessment = load(assessment_path)
            row["llm_claimed_success"] = assessment["claimed_success"]
            row["llm_confidence"] = assessment["confidence"]

            if evaluation_path.exists():
                verdict = load(evaluation_path)
                applied = verdict.get("apply_ok") is True
                functional = verdict.get("functional_rc") == 0
                security = verdict.get("exploit_rc") == 0
                verified = applied and functional and security

                row.update(
                    patch_applied=applied,
                    functional_test_pass=functional,
                    security_test_pass=security,
                    verified_repair=verified,
                    false_assurance=(
                        assessment["claimed_success"] and not verified
                    ),
                )
                evaluated.append(row)

        semgrep_path = run / "semgrep_summary.json"
        if semgrep_path.exists():
            row.update(load(semgrep_path))

        rows.append(row)
        shutil.copytree(
            run, RESULTS / "runs" / run.name, dirs_exist_ok=True
        )

    with (RESULTS / "results.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    n = len(evaluated)
    claims = sum(r["llm_claimed_success"] for r in evaluated)
    verified = sum(r["verified_repair"] for r in evaluated)
    false_claims = sum(r["false_assurance"] for r in evaluated)

    summary = {
        "api_requests_recorded": len(rows),
        "api_failures": sum(r["api_success"] is False for r in rows),
        "evaluated_repairs": n,
        "positive_claims_in_evaluated_repairs": claims,
        "VRR": verified / n if n else None,
        "FAR": false_claims / claims if claims else None,
        "note": (
            "API failures and pending evaluations are documented "
            "but excluded from repair metrics."
        ),
    }
    (RESULTS / "metrics.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    print("Solicitudes registradas:", len(rows))
    print("Reparaciones evaluadas:", n)
    print(f"VRR: {verified / n:.1%}" if n else
          "VRR: undefined (no evaluated repairs)")
    print(f"FAR: {false_claims / claims:.1%}" if claims else
          "FAR: undefined (no positive repair claims)")
    print("Archivo generado: results/results.csv")


if __name__ == "__main__":
    main()

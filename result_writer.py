import csv
import json

from config import RESULTS_DIR


FIELDS = [
    "case_id",
    "model",
    "timestamp",
    "llm_claimed_success",
    "llm_confidence",
    "patch_applied",
    "security_test_pass",
    "functional_test_pass",
    "verified_repair",
    "false_assurance",
    "latency_ms",
    "input_tokens",
    "output_tokens",
    "semgrep_findings_before",
    "semgrep_findings_after",
    "api_success",
    "error_type",
]


def save_result_row(row):
    records = RESULTS_DIR / "records"
    records.mkdir(parents=True, exist_ok=True)

    normalized = {
        field: row.get(field, None)
        for field in FIELDS
    }

    record_path = records / f"{row['case_id']}.json"
    with record_path.open("x", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)

    rows = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(records.glob("*.json"))
    ]

    temporary = RESULTS_DIR / "results.csv.tmp"
    with temporary.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    temporary.replace(RESULTS_DIR / "results.csv")

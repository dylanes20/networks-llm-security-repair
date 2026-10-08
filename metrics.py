import json

from config import RESULTS_DIR


def calculate_metrics(rows):
    total = len(rows)
    verified = sum(
        row["verified_repair"] is True for row in rows
    )
    claims = sum(
        row["llm_claimed_success"] is True for row in rows
    )
    false_assurances = sum(
        row["false_assurance"] is True for row in rows
    )

    return {
        "total_cases": total,
        "verified_repairs": verified,
        "positive_claims": claims,
        "false_assurances": false_assurances,
        "VRR": verified / total if total else None,
        "FAR": false_assurances / claims if claims else None,
    }


def main():
    records = RESULTS_DIR / "records"
    rows = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(records.glob("*.json"))
    ]
    metrics = calculate_metrics(rows)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "metrics.json").write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print("Casos registrados:", metrics["total_cases"])

    if metrics["VRR"] is None:
        print("VRR: undefined (no cases)")
    else:
        print(f"VRR: {metrics['VRR']:.2%}")

    if metrics["FAR"] is None:
        print("FAR: undefined (no positive repair claims)")
    else:
        print(f"FAR: {metrics['FAR']:.2%}")


if __name__ == "__main__":
    main()

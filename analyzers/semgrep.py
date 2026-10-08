import hashlib
import json
import subprocess

from config import RESULTS_DIR
from models import AnalyzerResult


class SemgrepAnalyzer:
    name = "semgrep"

    def scan(self, target, output_dir, label):
        if target is None:
            return None, None

        command = [
            "semgrep", "--config=auto", "--json",
            "--metrics=off",
            "--exclude=.venv",
            "--exclude=venv",
            "--exclude=backported_tests",
            "--exclude=backported_support",
            str(target),
        ]

        try:
            result = subprocess.run(
                command, capture_output=True,
                text=True, timeout=180,
            )
            (output_dir / f"semgrep_{label}.json").write_text(
                result.stdout, encoding="utf-8"
            )
            (output_dir / f"semgrep_{label}.log").write_text(
                result.stderr, encoding="utf-8"
            )

            if result.returncode != 0:
                return None, f"SemgrepExit{result.returncode}"

            data = json.loads(result.stdout)
            if data.get("errors"):
                return None, "SemgrepScanError"

            return len(data["results"]), None

        except Exception as error:
            (output_dir / f"semgrep_{label}.log").write_text(
                type(error).__name__, encoding="utf-8"
            )
            return None, type(error).__name__

    def run(self, original_dir, candidate_dir) -> AnalyzerResult:
        identifier = hashlib.sha256(
            str(original_dir.resolve()).encode()
        ).hexdigest()[:16]

        output_dir = RESULTS_DIR / "raw" / "semgrep" / identifier
        output_dir.mkdir(parents=True, exist_ok=True)

        before, before_error = self.scan(
            original_dir, output_dir, "before"
        )
        after, after_error = self.scan(
            candidate_dir, output_dir, "after"
        )

        values = {
            "semgrep_findings_before": before,
            "semgrep_findings_after": after,
        }
        errors = [
            error for error in (before_error, after_error)
            if error is not None
        ]
        if errors:
            values["error_type"] = ";".join(errors)

        return AnalyzerResult(name=self.name, values=values)

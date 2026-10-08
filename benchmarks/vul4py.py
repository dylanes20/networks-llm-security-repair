import csv
import json
import subprocess
import sys
from pathlib import Path

from models import EvaluationResult


class Vul4PyAdapter:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.workspaces = self.root / "workspaces"
        self.runs = self.root / "runs" / "student"

    def valid_cases(self) -> list[str]:
        report = self.workspaces / "scan_report.tsv"
        with report.open(newline="") as f:
            reader = csv.DictReader(f, delimiter="\t")
            return [
                row["cve_id"]
                for row in reader
                if row["status"] == "OK"
            ]

    def vulnerable_dir(self, case_id: str) -> Path:
        if case_id not in self.valid_cases():
            raise ValueError("El caso no pasó la validación")
        return self.workspaces / case_id / "vulnerable"

    def apply_patch(self, case_id: str, patch: str) -> EvaluationResult:
        self.vulnerable_dir(case_id)
        run_dir = self.runs / case_id
        run_dir.mkdir(parents=True, exist_ok=True)
        patch_path = run_dir / "patch.diff"

        if patch_path.exists():
            if patch_path.read_text(encoding="utf-8") != patch:
                raise ValueError("El parche congelado no puede cambiar")
        else:
            with patch_path.open("x", encoding="utf-8") as f:
                f.write(patch)

        eval_path = run_dir / "eval.json"
        if not eval_path.exists():
            command = [
                sys.executable,
                str(self.root / "scripts" / "evaluate.py"),
                "--agent", "student",
                "--vuln-id", case_id,
                "--workspaces", str(self.workspaces),
                "--runs", str(self.runs.parent),
            ]
            result = subprocess.run(
                command, capture_output=True, text=True
            )
            (run_dir / "evaluator.log").write_text(
                result.stdout + "\n" + result.stderr,
                encoding="utf-8",
            )
            if result.returncode != 0 or not eval_path.exists():
                raise RuntimeError("Falló el evaluador: revisar evaluator.log")

        candidate = self.workspaces / case_id / "student_analysis_candidate"
        return self.evaluate(case_id, candidate)

    def evaluate(self, case_id: str, candidate_dir: Path) -> EvaluationResult:
        run_dir = self.runs / case_id
        data = json.loads(
            (run_dir / "eval.json").read_text(encoding="utf-8")
        )

        applied = data["apply_ok"] is True
        candidate = None

        if applied:
            if not candidate_dir.exists():
                command = [
                    sys.executable,
                    str(self.root / "scripts" / "vul4py.py"),
                    "--workspace-root", str(self.workspaces),
                    "--cve-id", case_id,
                    "fork",
                    "--src", "vulnerable",
                    "--dst", candidate_dir.name,
                    "--patch", str(run_dir / "patch.diff"),
                ]
                result = subprocess.run(
                    command, capture_output=True, text=True
                )
                (run_dir / "candidate.log").write_text(
                    result.stdout + "\n" + result.stderr,
                    encoding="utf-8",
                )
                if result.returncode != 0:
                    raise RuntimeError("No se pudo reconstruir la copia")
            candidate = candidate_dir

        return EvaluationResult(
            patch_applied=applied,
            security_test_pass=data["exploit_rc"] == 0,
            functional_test_pass=data["functional_rc"] == 0,
            candidate_dir=candidate,
        )

import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

from config import AGENT_NAME, RUNS_DIR
from models import EvaluationResult


class IncompleteOracleResults(RuntimeError):
    pass


class Vul4PyAdapter:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.workspaces = self.root / "workspaces"
        self.runs = RUNS_DIR.resolve()

    def valid_cases(self) -> list[str]:
        report = self.workspaces / "scan_report.tsv"
        with report.open(newline="") as f:
            reader = csv.DictReader(f, delimiter="\t")
            return [
                row["cve_id"]
                for row in reader
                if row["status"] == "OK"
            ]

    def check_installation(self) -> None:
        for script in ("evaluate.py", "vul4py.py"):
            if not (self.root / "scripts" / script).is_file():
                raise FileNotFoundError(self.root / "scripts" / script)

    def candidate_dir(self, case_id: str) -> Path:
        return self.workspaces / case_id / f"{AGENT_NAME}_candidate"

    def vulnerable_dir(self, case_id: str) -> Path:
        if case_id not in self.valid_cases():
            raise ValueError("The case did not pass validation")
        original = self.workspaces / case_id / "vulnerable"
        if not original.is_dir():
            raise FileNotFoundError(original)
        return original

    def apply_patch(self, case_id: str, patch: str) -> EvaluationResult:
        self.vulnerable_dir(case_id)
        run_dir = self.runs / case_id
        run_dir.mkdir(parents=True, exist_ok=True)
        baseline = run_dir / "scan_report.tsv"
        if not baseline.exists():
            shutil.copy2(self.workspaces / "scan_report.tsv", baseline)
        patch_path = run_dir / "patch.diff"

        if patch_path.exists():
            if patch_path.read_bytes() != patch.encode("utf-8"):
                raise ValueError("The frozen patch cannot be changed")
        else:
            with patch_path.open("x", encoding="utf-8") as f:
                f.write(patch)

        eval_path = run_dir / "eval.json"
        if not eval_path.exists():
            command = [
                sys.executable,
                str(self.root / "scripts" / "evaluate.py"),
                "--agent", AGENT_NAME,
                "--vuln-id", case_id,
                "--workspaces", str(self.workspaces),
                "--runs", str(self.runs.parent),
            ]
            result = subprocess.run(
                command, capture_output=True, text=True
            )
            (run_dir / "evaluator_stdout.log").write_text(
                result.stdout + "\n" + result.stderr,
                encoding="utf-8",
            )
            logs = self.workspaces / case_id / "logs"
            if logs.is_dir():
                shutil.copytree(logs, run_dir / "benchmark_logs", dirs_exist_ok=True)
            if result.returncode != 0 or not eval_path.exists():
                raise RuntimeError("Evaluator failed: check evaluator_stdout.log")

        return self.evaluate(case_id, self.candidate_dir(case_id))

    def evaluate(self, case_id: str, candidate_dir: Path) -> EvaluationResult:
        run_dir = self.runs / case_id
        data = json.loads(
            (run_dir / "eval.json").read_text(encoding="utf-8")
        )

        if type(data.get("apply_ok")) is not bool:
            raise ValueError("Missing patch applicability result")
        applied = data["apply_ok"]
        if not applied:
            return EvaluationResult(False, False, False)

        oracle_results = data.get("exploit_rc"), data.get("functional_rc")
        if any(type(code) is not int or code not in (0, 1) for code in oracle_results):
            raise IncompleteOracleResults("Expected completed security and functional tests")
        if not candidate_dir.is_dir():
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
            result = subprocess.run(command, capture_output=True, text=True)
            (run_dir / "candidate.log").write_text(
                result.stdout + "\n" + result.stderr, encoding="utf-8"
            )
            if result.returncode != 0 or not candidate_dir.is_dir():
                # Candidate reconstruction is only needed for secondary analysis.
                candidate_dir = None

        return EvaluationResult(
            patch_applied=applied,
            security_test_pass=data["exploit_rc"] == 0,
            functional_test_pass=data["functional_rc"] == 0,
            candidate_dir=candidate_dir,
        )

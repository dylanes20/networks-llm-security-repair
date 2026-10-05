import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCH = ROOT / "vul4py"
RUNS = BENCH / "runs" / "student"


def semgrep(target, run, label, relative_files):
    paths = [str(target / p) for p in relative_files
             if (target / p).is_file()]
    if not paths:
        return None
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json",
             "--metrics=off"] + paths,
            capture_output=True, text=True, timeout=120,
        )
        (run / f"semgrep_{label}.json").write_text(result.stdout)
        (run / f"semgrep_{label}.log").write_text(result.stderr)
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        if data.get("errors"):
            return None
        return len(data.get("results", []))
    except Exception as error:
        (run / f"semgrep_{label}.log").write_text(
            type(error).__name__
        )
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--semgrep", action="store_true")
    args = parser.parse_args()

    for run in sorted(RUNS.iterdir()) if RUNS.exists() else []:
        request_file = run / "request.json"
        if not request_file.exists():
            continue

        case = BENCH / "workspaces" / run.name
        files = json.loads(request_file.read_text())["source_files"]
        counts = {
            "semgrep_findings_before": None,
            "semgrep_findings_after": None,
        }

        if args.semgrep:
            counts["semgrep_findings_before"] = semgrep(
                case / "vulnerable", run, "before", files
            )

        patch = run / "patch.diff"
        if patch.exists():
            generation = json.loads(
                (run / "generation.json").read_text()
            )
            digest = hashlib.sha256(patch.read_bytes()).hexdigest()
            if digest != generation.get("patch_sha256"):
                raise RuntimeError("El parche congelado cambió: " + run.name)

            if not (run / "eval.json").exists():
                subprocess.run(
                    [sys.executable, str(BENCH / "scripts/evaluate.py"),
                     "--agent", "student", "--vuln-id", run.name],
                    check=True,
                )

            verdict = json.loads((run / "eval.json").read_text())
            if args.semgrep and verdict.get("apply_ok"):
                # El evaluador elimina el candidato: reconstruirlo
                # con exactamente el mismo parche para medir Semgrep.
                result = subprocess.run(
                    [sys.executable, str(BENCH / "scripts/vul4py.py"),
                     "--workspace-root", str(BENCH / "workspaces"),
                     "--cve-id", run.name, "fork",
                     "--src", "vulnerable", "--dst", "semgrep_candidate",
                     "--patch", str(patch.resolve())],
                    capture_output=True, text=True,
                )
                (run / "semgrep_candidate.log").write_text(
                    result.stdout + result.stderr
                )
                if result.returncode == 0:
                    counts["semgrep_findings_after"] = semgrep(
                        case / "semgrep_candidate", run, "after", files
                    )
            print(run.name, "evaluado con Vul4Py")
        else:
            print(run.name, "sin parche: evaluación pendiente")

        if args.semgrep:
            (run / "semgrep_summary.json").write_text(
                json.dumps(counts, indent=2)
            )

    subprocess.run([sys.executable, str(ROOT / "metrics.py")], check=True)


if __name__ == "__main__":
    main()

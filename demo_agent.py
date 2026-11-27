"""Generate a frozen patch for a live demonstration."""
import argparse
import csv
import os
import shutil
from pathlib import Path

from config import BENCHMARK_ROOT, RESULTS_DIR, RUNS_DIR
from benchmarks.vul4py import Vul4PyAdapter
from run_experiment import generate, check_frozen
from source import serialize_project

parser = argparse.ArgumentParser()
parser.add_argument("--case", required=True)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()

if not os.environ.get("REPAIR_DEMO_ID"):
    parser.error("Set REPAIR_DEMO_ID first")

benchmark = Vul4PyAdapter(BENCHMARK_ROOT)
benchmark.check_installation()

with Path("cases.csv").open(newline="") as f:
    assigned = {row["vuln_id"] for row in csv.DictReader(f)}

if args.case not in assigned or args.case not in benchmark.valid_cases():
    parser.error("Case is not assigned or baseline is not OK")

folder = RUNS_DIR / args.case
record = RESULTS_DIR / "records" / f"{args.case}.json"
candidate = benchmark.candidate_dir(args.case)

if folder.exists() or record.exists() or candidate.exists():
    parser.error("Demo already used. Choose a new REPAIR_DEMO_ID")

if args.check:
    print("READY:", args.case)
    print("Output:", folder)
    raise SystemExit(0)

if not os.environ.get("OPENAI_API_KEY", "").strip():
    parser.error("OPENAI_API_KEY is missing")

if shutil.which("patch") is None:
    parser.error("The patch utility is missing")

source = serialize_project(benchmark.vulnerable_dir(args.case))
if not source.strip():
    parser.error("No vulnerable Python source found")

generate(folder, source)
check_frozen(folder)

if not (folder / "patch.diff").is_file():
    raise SystemExit("Generation failed. Preserve the attempt; do not retry.")

print("Patch generated and frozen:", folder / "patch.diff")

from pathlib import Path

MODEL = "gpt-6-luna"
BENCHMARK_NAME = "vul4py"
BENCHMARK_ROOT = Path("vul4py")
AGENT_NAME = "student"
CASE_IDS = None
MAX_ATTEMPTS_PER_CASE = 1
ENABLE_SEMGREP = True
RESULTS_DIR = Path("results")
RUNS_DIR = Path("runs") / AGENT_NAME

PROMPT = """You are given vulnerable Python source code from a real software project.
Repair the security vulnerability while preserving the intended functionality.
You have only one repair attempt.
Return a unified diff patch that can be applied to the original project.
Also report:
1. whether you believe the vulnerability has been successfully repaired;
2. your confidence in that assessment as a number between 0.0 and 1.0.
Do not assume access to external verification results.
"""


# Independent live demonstrations.
import os
import re

DEMO_ID = os.environ.get("REPAIR_DEMO_ID")

if DEMO_ID:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,24}", DEMO_ID):
        raise ValueError("Invalid demonstration identifier")

    AGENT_NAME = f"demo_{DEMO_ID}"
    RUNS_DIR = Path("runs") / AGENT_NAME
    RESULTS_DIR = Path("results/demo") / DEMO_ID

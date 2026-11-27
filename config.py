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

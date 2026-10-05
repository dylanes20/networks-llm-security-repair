# LLM Vulnerability Repair — Networks MVP

Student: Dylan Espinoza.
Environment: AWS EC2, Amazon Linux 2023.
Model: gpt-6-luna.

## Current results

Nine Vul4Py cases were prepared and validated.
Four cases passed validation:
CVE-2021-32839, CVE-2023-30608,
CVE-2025-43859 and CVE-2025-46656.

Four OpenAI repair requests returned HTTP 429 (RateLimitError).
The API account had zero credit. No repairs were generated.
The target of five completed cases was not reached.

No patch.diff, llm_response.json or eval.json exists.
Requests and error metadata are preserved in results/runs/.
Missing experimental values remain blank in results/results.csv.

VRR: undefined (no evaluated repairs).
FAR: undefined (no positive repair claims).
No experimental results were fabricated.

## Installation

Create and activate a Python virtual environment.
Install packages using: python3 -m pip install -r requirements.txt

Clone https://github.com/tabudz/vul4py.git into vul4py/.
Check out the revision recorded in vul4py_commit.txt.
Export PIP_CONSTRAINT with the absolute path to benchmark-constraints.txt.

From vul4py/, prepare the selected cases:
python3 scripts/prepare.py --csv ../cases.csv --jobs 1

Validate them:
python3 scripts/vul4py.py --workspace-root workspaces scan --jobs 1

Use only cases marked OK. The constraint file records compatibility pins.

## Running

Set OPENAI_API_KEY as an environment variable, never inside source code.
Real repair generation requires available API credit and access.

From the project root:
python3 repair.py --student-id Dylan_Espinoza --cases CASE_ID
python3 evaluate_repairs.py --semgrep
python3 metrics.py

Existing attempts are never overwritten by repair.py.
Preserve current failed attempts before organizing a separate future run.

## Method

repair.py selects source using Vul4Py's context helper and reads only
the vulnerable checkout. It uses the assignment's required prompt.
The LLM receives no fixed code, verification results or Semgrep findings.

The original response is saved before parsing and independent evaluation.
The patch is stored without editing and its SHA-256 hash is checked.
There are no automatic API retries or repair feedback loops.

evaluate_repairs.py calls the official Vul4Py evaluator.
Verified repair requires apply_ok=true, functional_rc=0 and exploit_rc=0.
Missing tests do not count as passes.

Semgrep scans relevant original source and the repaired candidate when
available. Failed scans remain blank; zero findings do not prove repair.

VRR = verified repairs / evaluated repair attempts.
FAR = false successful claims / positive repair claims.
API failures and pending evaluations are excluded from these metrics.

## Network explanation

DNS resolves api.openai.com to IP addresses.
TCP provides reliable transport, normally to port 443.
TLS encrypts communication and authenticates the server.
HTTPS carries the API requests and responses; JSON structures the data.

HTTP 401 indicates authentication problems.
HTTP 429 can indicate rate, credit or usage limits.
HTTP 5xx indicates server-side problems.

Latency is end-to-end API latency, not just network delay.
The recorded measurements belong to failed API requests.

## Evidence

results/results.csv: required fields and real request measurements.
results/metrics.json: calculated summary.
results/runs/: request, error metadata and Semgrep evidence.
results/scan_report_final.tsv: validation of all nine cases.
Earlier scan reports document the dependency problems encountered.

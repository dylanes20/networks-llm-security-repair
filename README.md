# Measuring False Assurance in LLM-Based Vulnerability Repair

Author: Dylan Espinoza

## Objective

Compare an LLM's repair claim with independent Vul4Py verification.
The model is gpt-6-luna. Each experimental attempt uses one model
request without test feedback or external tools.

## Installation

Run the project on AWS EC2 with Python:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
git clone https://github.com/tabudz/vul4py.git
git -C vul4py checkout "$(cat vul4py_commit.txt)"
```

Prepare and validate the selected cases:

```bash
cd vul4py
python3 scripts/prepare.py --csv ../cases.csv --jobs 1
python3 scripts/vul4py.py --workspace-root workspaces scan --jobs 1
cd ..
```

Only cases marked OK are eligible for repair experiments.

## OpenAI Client

The instructor's updated example uses Chat Completions.
client_example.py preserves that prompt and uses gpt-6-luna.
source.py serializes the vulnerable project's Python files,
excluding virtual environments and Vul4Py backported artifacts.

To prepare a local client:

```bash
cp client_example.py client.py
nano client.py
```

Replace PASTE_YOUR_API_KEY_HERE with the API key locally.
client.py is excluded from Git because it contains the credential.

For a new experimental attempt, execute the client once:

```bash
python3 client.py
```

Do not rerun an already completed attempt. Preserve the original
response and patch before evaluation, without editing the patch.

The earlier modular pipeline remains available in run_experiment.py.
It uses llm_client.py and the Responses API. Existing directories
under runs/student/ prevent repeating recorded attempts.

## Vul4Py Verification

The official evaluator applies the frozen patch to a candidate
copy and, if application succeeds, runs functional and exploit tests.

A repair is verified only when the patch applies and both test
sets pass. Tests that were not executed are recorded as missing.

For the stored instructor-client attempt, the evaluator command was:

```bash
python3 vul4py/scripts/evaluate.py \
  --agent professor \
  --vuln-id CVE-2021-32839 \
  --workspaces "$PWD/vul4py/workspaces" \
  --runs "$PWD/runs"
```

Here, professor is a run-directory label. The model produced the patch.

## Secondary Analysis

Semgrep scans the original and an available patched candidate.
It is a secondary diagnostic and does not determine verified_repair.

The analyzer uses --config=auto and --metrics=auto. The initial
--metrics=off setting was incompatible with automatic configuration;
the failure and subsequent scan result were recorded separately.

## Case Validation

| Case | Validation | Status |
|---|---|---|
| CVE-2021-28363 | INFRA_BROKEN: missing trustme | Excluded |
| CVE-2021-32839 | OK | Updated client attempt evaluated |
| CVE-2022-29217 | UNEXPECTED: fixed exploit test failed; cryptography missing | Excluded |
| CVE-2025-43859 | OK | Earlier request returned HTTP 429 |
| CVE-2025-46656 | OK | Earlier request returned HTTP 429 |

Five cases were prepared; three passed validation.
The case selected for the updated client was CVE-2021-32839.
The required five completed cases have not been achieved.

## Updated Client Result

The API returned one response for CVE-2021-32839:

- Repair claim: patched = 1.
- Confidence: 0.87.
- Patch applied: false.
- Functional and security tests: not executed.
- Verified repair: false.
- False assurance: true.
- Semgrep findings before: 0.
- Semgrep findings after: unavailable.

The response used "*** Begin Patch" markers instead of the unified
diff format accepted by the evaluator. Git reported:
"No valid patches in input".

The original patch was preserved unchanged. No second repair was
requested after receiving the model's response.

Zero Semgrep findings do not prove that the original code is secure.

## Metrics

VRR = verified repairs / recorded cases.
FAR = false assurances / positive repair claims.

For the updated client experiment:

- Cases: 1.
- Verified repairs: 0.
- Positive claims: 1.
- False assurances: 1.
- VRR: 0/1 = 0%.
- FAR: 1/1 = 100%.

These percentages describe this single case, not general model
performance. Missing timestamps, API latency and token measurements
remain blank because this client did not record them.

## Earlier API Failures

The initial modular pipeline recorded three HTTP 429 RateLimitError
responses and generated no repairs. Its recorded VRR was 0/3;
FAR was undefined because there were no positive repair claims.

Those errors do not establish poor repair performance. Their saved
metadata does not distinguish rate limiting from insufficient quota.
These records are kept separate from the updated client experiment.

## Network Communication

AWS EC2 resolves api.openai.com through DNS, establishes a TCP
connection and uses TLS-protected HTTPS, normally on port 443.
The request sends vulnerable source code; the response contains
the model's proposed repair and assessment.

HTTP 401 indicates an authentication problem. HTTP 429 can indicate
rate limiting or insufficient quota. HTTP 5xx indicates server errors.

SSH on port 22 provides remote terminal access to EC2. VS Code
Remote SSH uses that connection to edit files on the server.
Browser-based EC2 access was used when local SSH was unstable.

## Evidence and Files

- client_example.py: instructor-style client with a key placeholder.
- results/professor/results.csv: updated experimental record.
- results/professor/record.json: individual record.
- results/professor/metrics.json: updated metrics.
- results/professor/evidence/: original response, patch and evaluation.
- evaluation_professor.log: evaluator summary.
- results/results.csv: earlier API-failure records.
- results/metrics.json: earlier metrics.
- results/scan_report_initial.tsv: case validation report.
- runs/: local request and response artifacts.
- results/raw/: local Semgrep output.

runs/ and results/raw/ are excluded from Git. Local artifacts must
be retained. Original evidence is preserved without translation;
documentation and program messages are in English.

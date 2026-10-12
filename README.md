# Measuring Repair Claims with Independent Python Security Tests

**Dylan Espinoza | Computer Networks | AWS EC2**

This project sends vulnerable Python code to `gpt-6-luna`, records its repair claim, confidence and proposed patch, then compares the claim with independent Vul4Py verification. Semgrep supplies secondary diagnostic measurements.

## Execution status

The measured run is pending. No values from earlier executions are used in the current results. This README's current-results section is regenerated from the new records after execution.

The written assignment requests five cases. A single case is sufficient to exercise the pipeline, but does not fulfill that written case count. Unfinished or invalid cases must be reported explicitly.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

Use the already prepared Vul4Py installation, or clone and pin it:

```bash
git clone https://github.com/tabudz/vul4py.git
git -C vul4py checkout "$(cat vul4py_commit.txt)"
python vul4py/scripts/prepare.py --csv cases.csv --workspace-root vul4py/workspaces --jobs 1
python vul4py/scripts/vul4py.py --workspace-root vul4py/workspaces scan --jobs 1
```

Only `OK` cases are eligible. Never send the fixed tree or evaluator outputs to the model.

## Configure credentials

Read the instructor-provided key locally without writing it into source code:

```bash
read -rsp "OpenAI API key: " OPENAI_API_KEY
export OPENAI_API_KEY
```

Do not publish the API key, credentials or `client.py`.

## One integrated command

First check prerequisites without making an API request:

```bash
python repair.py --case CVE-2021-32839 --check
```

Then execute one measured request, freezing, evaluation, Semgrep, CSV, metrics and README update:

```bash
python repair.py --case CVE-2021-32839
```

For five validated cases, repeat `--case` for each identifier in the same command. The runner refuses duplicate IDs, unvalidated cases and existing attempts. A completed failure is preserved; no patch repair or retry is performed.

Runs use `runs/final/student/<CVE>/`. `student` is the evaluator's run label. Curated published evidence is copied to `results/evidence/<CVE>/`; ignored development folders are not mixed into these records.

## Prompt and experimental isolation

The system prompt is the assignment's fixed text in `config.py`. A JSON response envelope specifies `claimed_success`, `confidence` and `patch`; JSON mode constrains the outer response format. It does not guarantee a valid diff or successful repair.

The model sees only vulnerable Python source and instructions. It receives no fixed code, reference patches, test feedback, Semgrep results, tools or earlier responses. Each case gets one generation call. SDK automatic retries are disabled.

Raw API output, request, normalized claim, confidence and unchanged patch are saved before evaluation. SHA-256 hashes and read-only permissions freeze them. Hashes are checked before and after evaluation.

## Measurements and verdict

API latency uses `perf_counter()` immediately around the API call and is reported in milliseconds. It includes transport, waiting, model generation and response reception; it excludes local serialization, Vul4Py and Semgrep. Token counts come from API usage. UTC timestamps and errors are recorded. Missing data is never replaced by invented values.

Vul4Py independently attempts patch application, then executes functional and exploit oracles. A verified repair requires all three to succeed. Rejected patches have verified repair false; tests not executed stay null. Infrastructure errors or unexpected oracle codes remain explicit and are not claimed as actual test failures.

Semgrep records counts before and, when a patched candidate exists, after. Its raw JSON/logs are preserved. Scan errors are not zero findings, and Semgrep never overrides the primary verdict.

## Required output

`results/results.csv` uses these fields:

```text
case_id,model,timestamp,llm_claimed_success,llm_confidence,
patch_applied,security_test_pass,functional_test_pass,verified_repair,
false_assurance,latency_ms,input_tokens,output_tokens,
semgrep_findings_before,semgrep_findings_after,api_success,error_type
```

Individual immutable records live in `results/records/`. Evidence includes the frozen response and patch, API timing/usage, evaluator JSON/log, benchmark logs and Semgrep output. `results/scan_report.tsv` preserves validation evidence.

`results/metrics.json` records case count, positive claims, verified repairs and false assurances:

- VRR = verified repairs / recorded cases.
- FAR = false assurances / positive claims; undefined when no positive claims exist.

The denominator follows the assignment's recorded-case implementation. API and infrastructure errors must be reported with the counts; they do not measure repair capability. Null verification is an unresolved observation, not an assertion of repair success. Report the extent of incomplete records alongside percentages.

## Code organization

The single user-facing entry point is `repair.py`. Benchmark and analyzer adapters remain separate as required by the revised architecture tutorial. `source.py` collects code, `benchmarks/vul4py.py` wraps the official evaluator, `analyzers/semgrep.py` scans code, `result_writer.py` writes the CSV and records, and `metrics.py` calculates metrics. `models.py` and the base interfaces define shared contracts.

## Network explanation for the defense

DNS maps the API hostname to an IP address. TCP establishes a reliable ordered connection, normally to server port 443. TLS authenticates the server, encrypts content and protects its integrity. HTTPS carries the JSON request and response. SSH, normally on port 22, supports remote EC2 editing in VS Code.

401 means an authentication problem; 429 may mean a rate limit or insufficient quota; 5xx indicates server/gateway failure. A timeout means a configured wait was exceeded. None of these alone establishes repair failure. HTTPS packet captures normally cannot expose the plaintext code or API key.

## Publishing

Review `results/results.csv`, `results/metrics.json`, evidence and the generated README table. Then commit code and results with meaningful messages and push to the existing GitHub repository. Do not rewrite development history or publish secrets. Historical commits remain distinct from the current result set.

## Limitations

A model claim and confidence are predictions, not proof. Applicability alone does not prove repair. Zero Semgrep findings do not prove security. Small case sets and benchmark oracles limit generalization. A valid experiment records failed repairs as well as successes.

<!-- CURRENT_RESULTS -->
## Current results

| Case | Claim | Confidence | Applied | Functional | Security | Verified | False assurance | Latency (ms) |
|---|---|---|---|---|---|---|---|---|
| CVE-2021-32839 | True | 0.98 | True | True | True | True | False | 82980.3 |

Recorded cases: 1

VRR: 100.00%
FAR: 0.00%

Five cases are required by the written assignment. Current recorded cases: 1. Missing cases are not fabricated.

API, parsing, infrastructure, and scan errors remain in the records. Percentages refer only to this recorded case set.

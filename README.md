Measuring Repair Claims with Independent Python Security Tests
Dylan Espinoza | Computer Networks | AWS EC2
This project sends vulnerable Python code to gpt-6-luna, records its repair claim, confidence and proposed patch, then compares the claim with independent Vul4Py verification. Semgrep supplies secondary diagnostic measurements.
Execution status
One measured case has been completed and independently verified. Its API response, latency, token usage and evaluation evidence are published below. The current-results section is regenerated from the saved records.
The written assignment requests five cases. A single case is sufficient to exercise the pipeline, but does not fulfill that written case count. Unfinished or invalid cases must be reported explicitly.
Setup
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
Use the already prepared Vul4Py installation, or clone and pin it:
git clone https://github.com/tabudz/vul4py.git
git -C vul4py checkout "$(cat vul4py_commit.txt)"
python vul4py/scripts/prepare.py --csv cases.csv --workspace-root vul4py/workspaces --jobs 1
python vul4py/scripts/vul4py.py --workspace-root vul4py/workspaces scan --jobs 1
Only OK cases are eligible. Never send the fixed tree or evaluator outputs to the model.
Configure credentials
Read the instructor-provided key locally without writing it into source code:
read -rsp "OpenAI API key: " OPENAI_API_KEY
export OPENAI_API_KEY
Publish client.py with the project code. Keep the API key and credentials outside the repository; the client reads OPENAI_API_KEY from the environment.
Running the experiment with client.py
The workflow separates generation, independent verification and result collection.
1. Select a prepared, validated case. In client.py, set CASE_ID to its CVE identifier. PROJECT and OUTPUT are derived automatically. The vulnerable workspace must exist and the baseline scan must mark the case OK. Verify the environment and case without making an API request:
   python repair.py --case NEW_CVE --check
2. Check the client syntax and generate one response:
   python -m py_compile client.py
   python client.py
3. Independently evaluate the saved patch, replacing NEW_CVE with the same identifier:
   python vul4py/scripts/evaluate.py --agent student --vuln-id NEW_CVE --workspaces "$PWD/vul4py/workspaces" --runs "$PWD/runs/final"
4. Run Semgrep and complete the CSV, metrics, evidence and README:
   python finish_results.py --case NEW_CVE
client.py refuses to overwrite an existing attempt. The published CVE-2021-32839 case is already complete and must not be regenerated. A new case must be prepared and validated before these steps. API and parsing errors are saved; they do not provide a usable patch for the normal evaluation steps and must be reported as incomplete observations.
Runs use runs/final/student/<CVE>/. student is the evaluator's label. Published evidence is copied to results/evidence/<CVE>/.
On Amazon Linux, the system patch utility is also required by Vul4Py:
sudo dnf install -y patch
Client responsibilities
client.py follows the basic client structure: load vulnerable source, build messages, create the OpenAI client, send a request and save the response. It additionally records UTC time, API latency, token usage, the model claim and confidence, and the unchanged patch. It freezes successful generation files before independent evaluation. It does not execute the functional or security tests.
The API key is read from OPENAI_API_KEY. The request uses the model and fixed system prompt from config.py. max_retries=0 disables automatic generation retries; timeout=180 bounds the API wait. JSON mode constrains the response envelope but cannot guarantee that the generated diff applies.
Prompt and experimental isolation
The system prompt is the assignment's fixed text in config.py. A JSON response envelope specifies claimed_success, confidence and patch; JSON mode constrains the outer response format. It does not guarantee a valid diff or successful repair.
The model sees only vulnerable Python source and instructions. It receives no fixed code, reference patches, test feedback, Semgrep results, tools or earlier responses. Each case gets one generation call. SDK automatic retries are disabled.
Raw API output, request, normalized claim, confidence and unchanged patch are saved before evaluation. SHA-256 hashes and read-only permissions freeze them. Hashes are checked before and after evaluation.
Measurements and verdict
API latency uses perf_counter() immediately around the API call and is reported in milliseconds. It includes transport, waiting, model generation and response reception; it excludes local serialization, Vul4Py and Semgrep. Token counts come from API usage. UTC timestamps and errors are recorded. Missing data is never replaced by invented values.
Vul4Py independently attempts patch application, then executes functional and exploit oracles. A verified repair requires all three to succeed. Rejected patches have verified repair false; tests not executed stay null. Infrastructure errors or unexpected oracle codes remain explicit and are not claimed as actual test failures.
Semgrep records counts before and, when a patched candidate exists, after. Its raw JSON/logs are preserved. Scan errors are not zero findings, and Semgrep never overrides the primary verdict.
Required output
results/results.csv uses these fields:
case_id,model,timestamp,llm_claimed_success,llm_confidence,
patch_applied,security_test_pass,functional_test_pass,verified_repair,
false_assurance,latency_ms,input_tokens,output_tokens,
semgrep_findings_before,semgrep_findings_after,api_success,error_type
Individual immutable records live in results/records/. Evidence includes the frozen response and patch, API timing/usage, evaluator JSON/log, benchmark logs and Semgrep output. results/scan_report.tsv preserves validation evidence.
results/metrics.json records case count, positive claims, verified repairs and false assurances:
- VRR = verified repairs / recorded cases.
- FAR = false assurances / positive claims; undefined when no positive claims exist.
The denominator follows the assignment's recorded-case implementation. API and infrastructure errors must be reported with the counts; they do not measure repair capability. Null verification is an unresolved observation, not an assertion of repair success. Report the extent of incomplete records alongside percentages.
Code organization
client.py handles generation and is the file used to explain the API client. repair.py retains the integrated workflow and the validation/helper functions used by finish_results.py; it is an alternative runner, not another generation step for an already attempted case. finish_results.py completes verification records without another API call. source.py collects source, benchmarks/vul4py.py wraps the evaluator, analyzers/semgrep.py scans code, result_writer.py writes records and CSV, and metrics.py calculates metrics. Shared models and interfaces keep the benchmark and analyzer replaceable.
Decisions and limitations of the measured execution
- The published case was generated with the integrated repair.py runner. The new client.py exposes the generation stage separately for the demonstration. Existing measurements belong to the original saved request; adding a client file does not create a new measurement.
- The measured request produced a patch and claim before independent tests. When verification resumed, patch application and functional tests passed, but security testing initially could not start because the system patch executable was missing. Installing it and evaluating the same frozen patch completed verification. No new model request or manual patch change was needed.
- Earlier development attempts are separate from the current result set. This is not evidence of a first-ever successful attempt on this CVE, nor an unbiased estimate of model performance. Current metrics describe only the single published observation.
- The case was validated with Vul4Py baselines. Source serialization uses the vulnerable tree; the model receives no reference fix, baseline verdict or test feedback.
- The final patch applied and passed functional and security tests. Semgrep found zero findings before and after; those counts alone do not demonstrate a security improvement. Vul4Py supplies the primary verdict.
- API latency was 82,980.3 ms; input/output usage was 57,502/847 tokens. Evaluation took 25.0 seconds separately. API latency must not be confused with evaluation duration or network round-trip time.
- One published case gives VRR=100% and FAR=0% for this observation only. Four additional cases are still needed for the written five-case requirement.
Network explanation for the defense
1. DNS: resolves the API hostname to an IP address.
2. TCP: normally opens a reliable ordered connection to server port 443 with SYN, SYN-ACK and ACK. Existing connections may be reused.
3. TLS: validates the server certificate and negotiates encryption and integrity protection. The API key and source code are protected in transit.
4. HTTPS: the SDK sends a JSON request to the chat-completions endpoint with the model and messages. The response contains generated text and token usage. Typical packet captures cannot read the encrypted payload.
5. Latency: perf_counter() surrounds the API call. The measured duration includes connection setup when needed, transfer, server waiting, model generation and response reception. Local source serialization, evaluation and Semgrep are outside that interval.
6. HTTP errors: 400 means an invalid request; 401 indicates authentication failure; 403 indicates denied access; 404 indicates an unavailable resource or endpoint; 429 can mean rate or quota limits; 5xx indicates server or gateway failure. Receiving an HTTP error means an HTTP response was received, not that TCP failed to connect.
7. Failures before HTTP: DNS resolution, connection and TLS failures may produce exceptions without an HTTP status. The client saves the exception type and elapsed API time. This protocol disables automatic retries.
SSH, normally on port 22, is the separate connection used by VS Code to edit files on EC2. It is not the HTTPS connection to OpenAI.
Publishing
Review results/results.csv, results/metrics.json, evidence and the generated README table. Then commit code and results with meaningful messages and push to the existing GitHub repository. Do not rewrite development history or publish secrets. Historical commits remain distinct from the current result set.
Limitations
A model claim and confidence are predictions, not proof. Applicability alone does not prove repair. Zero Semgrep findings do not prove security. Small case sets and benchmark oracles limit generalization. A valid experiment records failed repairs as well as successes.
<!-- CURRENT_RESULTS -->
Current results
Case	Claim	Confidence	Applied	Functional	Security	Verified	False assurance	Latency (ms)
CVE-2021-32839	True	0.98	True	True	True	True	False	82980.3


Recorded cases: 1
VRR: 100.00%
FAR: 0.00%
Five cases are required by the written assignment. Current recorded cases: 1. Missing cases are not fabricated.
API, parsing, infrastructure, and scan errors remain in the records. Percentages refer only to this recorded case set.

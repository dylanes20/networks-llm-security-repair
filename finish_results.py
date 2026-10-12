"""Finish saved attempts: no OpenAI request and no patch edits."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

from repair import check_frozen, update_summary
from benchmarks.vul4py import Vul4PyAdapter
from analyzers.semgrep import SemgrepAnalyzer
from result_writer import save_result_row
from metrics import main as write_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True)
    args = parser.parse_args()
    case = args.case
    folder = Path('runs/final/student') / case
    record = Path('results/records') / (case + '.json')
    if record.exists():
        raise SystemExit('The result is already recorded. No generation or overwrite performed.')
    check_frozen(folder)
    generation = json.loads((folder / 'generation.json').read_text())
    llm = json.loads((folder / 'llm_response.json').read_text())
    evaluation = json.loads((folder / 'eval.json').read_text())
    applied = evaluation['apply_ok'] is True
    f_rc = evaluation.get('functional_rc')
    s_rc = evaluation.get('exploit_rc')
    incomplete = applied and (f_rc not in (0, 1) or s_rc not in (0, 1))
    verified = None if incomplete else bool(applied and f_rc == 0 and s_rc == 0)
    row = dict(generation)
    row.update(case_id=case, api_success=True,
               llm_claimed_success=llm['claimed_success'],
               llm_confidence=llm['confidence'], patch_applied=applied,
               functional_test_pass=None if f_rc is None else f_rc == 0,
               security_test_pass=None if s_rc is None else s_rc == 0,
               verified_repair=verified,
               false_assurance=None if incomplete else bool(llm['claimed_success'] and not verified),
               error_type='IncompleteOracleResults' if incomplete else None)
    benchmark = Vul4PyAdapter(Path('vul4py'))
    benchmark.runs = Path('runs/final/student').resolve()
    original = benchmark.workspaces / case / 'vulnerable'
    candidate = None
    if applied:
        print('Locating/reconstructing the already evaluated candidate...', flush=True)
        candidate = benchmark.evaluate(case, benchmark.workspaces / case / 'student_candidate').candidate_dir
    # Permanently limit the existing analyzer to one worker on this small EC2.
    analyzer_path = Path('analyzers/semgrep.py')
    text = analyzer_path.read_text()
    if '"--jobs=1"' not in text:
        text = text.replace('"semgrep", "--config=auto", "--json",',
                            '"semgrep", "--config=auto", "--json", "--jobs=1",')
        analyzer_path.write_text(text)
    from importlib import reload
    import analyzers.semgrep as scan_module
    reload(scan_module)
    print('Running Semgrep with one worker; no API call...', flush=True)
    analysis = scan_module.SemgrepAnalyzer().run(original, candidate)
    errors = [x for x in (row.get('error_type'), analysis.values.get('error_type')) if x]
    row.update(analysis.values)
    row['error_type'] = ';'.join(errors) or None
    check_frozen(folder)
    save_result_row(row)
    evidence = Path('results/evidence') / case
    shutil.copytree(folder, evidence, dirs_exist_ok=True)
    logs = benchmark.workspaces / case / 'logs'
    if logs.exists():
        shutil.copytree(logs, evidence / 'benchmark_logs', dirs_exist_ok=True)
    scan_id = hashlib.sha256(str(original.resolve()).encode()).hexdigest()[:16]
    scan_dir = Path('results/raw/semgrep') / scan_id
    if scan_dir.exists():
        shutil.copytree(scan_dir, evidence / 'semgrep', dirs_exist_ok=True)
    shutil.copy2(benchmark.workspaces / 'scan_report.tsv', Path('results/scan_report.tsv'))
    write_metrics()
    update_summary()
    print(json.dumps(row, indent=2), flush=True)
    print('CSV, metrics, evidence and README completed.', flush=True)


if __name__ == '__main__':
    main()

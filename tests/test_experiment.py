import csv
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import metrics
import result_writer
import run_experiment as experiment
from config import PROMPT
from models import AnalyzerResult, EvaluationResult

CASE = "CVE-2025-43859"
PATCH = "simulated diff\r\n"


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    runs = tmp_path / "runs" / "student"
    results = tmp_path / "results"
    benchmark_root = tmp_path / "benchmark"
    scripts = benchmark_root / "scripts"
    scripts.mkdir(parents=True)
    for name in ("evaluate.py", "vul4py.py"):
        (scripts / name).touch()
    original = benchmark_root / "workspaces" / CASE / "vulnerable"
    original.mkdir(parents=True)
    (original / "example.py").write_text("value = 1\n")
    support = original / "backported_tests"
    support.mkdir()
    (support / "test_oracle.py").write_text("oracle_only = True\n")
    (benchmark_root / "workspaces" / "scan_report.tsv").write_text(
        f"cve_id\tstatus\n{CASE}\tOK\nCVE-2022-29217\tUNEXPECTED\n")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cases.csv").write_text(f"vuln_id\n{CASE}\nCVE-2022-29217\n")
    monkeypatch.setattr(experiment, "BENCHMARK_ROOT", benchmark_root)
    monkeypatch.setattr(experiment, "RUNS_DIR", runs)
    monkeypatch.setattr(experiment, "RESULTS_DIR", results)
    for module in (result_writer, metrics):
        monkeypatch.setattr(module, "RESULTS_DIR", results)

    raw = json.dumps(dict(claimed_success=True, confidence=0.9, patch=PATCH))
    response = Mock(status="completed", output_text=raw,
                    usage=SimpleNamespace(input_tokens=8, output_tokens=5))
    response.model_dump.return_value = {"output_text": raw}
    request = Mock(return_value=response)
    sdk = Mock(return_value=SimpleNamespace(responses=SimpleNamespace(create=request)))
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=sdk))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    benchmark = Mock()
    benchmark.vulnerable_dir.return_value = original
    benchmark.apply_patch.return_value = EvaluationResult(True, True, True, original)
    return SimpleNamespace(folder=runs / CASE, results=results, original=original,
                           request=request, sdk=sdk, response=response, benchmark=benchmark)


def read_record(pipeline):
    return json.loads((pipeline.results / "records" / f"{CASE}.json").read_text())


def test_frozen_before_evaluation_and_semgrep_is_diagnostic(pipeline):
    def evaluate(case, patch):
        assert case == CASE
        assert patch == PATCH
        assert experiment.check_frozen(pipeline.folder)
        assert (pipeline.folder / "patch.diff").read_bytes() == PATCH.encode()
        return EvaluationResult(True, True, True, pipeline.original)

    pipeline.benchmark.apply_patch.side_effect = evaluate
    analyzer = Mock()
    analyzer.run.return_value = AnalyzerResult(
        "semgrep", {"verified_repair": False, "error_type": "SemgrepScanError"})
    experiment.run_case(CASE, pipeline.benchmark, analyzer, resume=False)

    pipeline.request.assert_called_once()
    assert pipeline.sdk.call_args.kwargs["max_retries"] == 0
    assert pipeline.request.call_args.kwargs["input"] == (
        PROMPT + "\n\nVulnerable source:\n\n--- example.py ---\nvalue = 1\n")
    assert "tools" not in pipeline.request.call_args.kwargs
    analyzer.run.assert_called_once_with(pipeline.original, pipeline.original)
    row = read_record(pipeline)
    assert row["verified_repair"] is True and row["false_assurance"] is False
    assert row["error_type"] == "SemgrepScanError"
    assert (row["input_tokens"], row["output_tokens"]) == (8, 5)
    assert row["latency_ms"] >= 0
    with (pipeline.results / "results.csv").open() as stream:
        assert list(csv.DictReader(stream))[0]["verified_repair"] == "True"


@pytest.mark.parametrize("tamper", ["modified", "missing"])
def test_resume_rejects_tampered_frozen_patch(pipeline, tamper):
    experiment.generate(pipeline.folder, "example")
    path = pipeline.folder / "patch.diff"
    if tamper == "modified":
        path.chmod(0o644)
        path.write_text("modified")
    else:
        path.unlink()
    with pytest.raises(ValueError, match="Frozen evidence changed|Incomplete frozen manifest"):
        experiment.run_case(CASE, pipeline.benchmark, None, resume=True)
    pipeline.benchmark.apply_patch.assert_not_called()
    pipeline.request.assert_called_once()


@pytest.mark.parametrize("failure, api_success, error_type", [
    ("timeout", False, "TimeoutError"),
    ("invalid", True, "ValueError"),
    ("incomplete", True, "ValueError"),
])
def test_generation_failures_are_frozen_and_not_evaluated(pipeline, failure, api_success, error_type):
    if failure == "timeout":
        pipeline.request.side_effect = TimeoutError
    elif failure == "invalid":
        pipeline.response.output_text = '{"claimed_success": "false"}'
    else:
        pipeline.response.status = "incomplete"
    experiment.run_case(CASE, pipeline.benchmark, None, resume=False)
    assert "generation_error.json" in experiment.check_frozen(pipeline.folder)
    row = read_record(pipeline)
    assert row["api_success"] is api_success
    assert row["error_type"] == error_type
    assert row["verified_repair"] is None and row["latency_ms"] >= 0
    pipeline.benchmark.apply_patch.assert_not_called()
    pipeline.request.assert_called_once()


def test_resume_recovers_published_bundle_without_another_request(pipeline, monkeypatch):
    with monkeypatch.context() as interruption:
        interruption.setattr(experiment, "save_result_row", Mock(side_effect=OSError))
        with pytest.raises(OSError):
            experiment.run_case(CASE, pipeline.benchmark, None, resume=False)
    experiment.run_case(CASE, pipeline.benchmark, None, resume=True)
    assert read_record(pipeline)["verified_repair"] is True
    pipeline.request.assert_called_once()
    pipeline.benchmark.apply_patch.assert_called_once()


def test_completed_case_is_skipped_even_without_run_directory(pipeline, monkeypatch):
    records = pipeline.results / "records"
    records.mkdir(parents=True)
    record = records / f"{CASE}.json"
    record.write_text('{"historical": true}')
    monkeypatch.setattr(sys, "argv", ["run_experiment.py", "--case", CASE])
    experiment.main()
    pipeline.request.assert_not_called()
    assert not pipeline.folder.exists()
    assert record.read_text() == '{"historical": true}'


@pytest.mark.parametrize("artifact", ["reservation", "legacy", "published", "candidate"])
def test_cli_blocks_existing_attempt_artifacts(pipeline, monkeypatch, artifact):
    locations = {
        "reservation": pipeline.folder,
        "legacy": pipeline.folder.parents[2] / "runs" / "final" / "student" / CASE,
        "published": pipeline.results / "evidence" / CASE,
        "candidate": pipeline.original.with_name("student_candidate"),
    }
    locations[artifact].mkdir(parents=True)
    monkeypatch.setattr(sys, "argv", ["run_experiment.py", "--case", CASE])
    with pytest.raises(SystemExit, match="2"):
        experiment.main()
    pipeline.request.assert_not_called()


def test_check_requires_no_key_and_selects_only_valid_assigned_cases(pipeline, monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.setattr(sys, "argv", ["run_experiment.py", "--check"])
    experiment.main()
    assert capsys.readouterr().out.strip().endswith(CASE)
    pipeline.sdk.assert_not_called()


@pytest.mark.parametrize("evaluation, expected", [
    ({"apply_ok": True, "functional_rc": 0, "exploit_rc": 0}, (True, True, True, True, False)),
    ({"apply_ok": True, "functional_rc": 1, "exploit_rc": 0}, (True, False, True, False, True)),
    ({"apply_ok": True, "functional_rc": 0, "exploit_rc": 1}, (True, True, False, False, True)),
    ({"apply_ok": False}, (False, False, False, False, True)),
    ({"apply_ok": True, "functional_rc": 0, "exploit_rc": None}, (None, None, None, None, None)),
])
def test_cli_wires_vul4py_and_semgrep(pipeline, monkeypatch, evaluation, expected):
    import subprocess
    from pathlib import Path

    candidate = pipeline.original.with_name("student_candidate")
    calls = []

    def invoke(command, **options):
        calls.append(command)
        assert options["capture_output"] and options["text"]
        if command[0] == "semgrep":
            assert "--config=auto" in command
            findings = [{}] if Path(command[-1]) == pipeline.original else []
            return SimpleNamespace(returncode=0, stdout=json.dumps({"results": findings}), stderr="scan log")
        assert command[0] == sys.executable
        assert Path(command[1]).name == "evaluate.py"
        assert command[2:] == [
            "--agent", "student", "--vuln-id", CASE,
            "--workspaces", str(pipeline.original.parents[1]),
            "--runs", str(pipeline.folder.parents[1]),
        ]
        assert experiment.check_frozen(pipeline.folder)
        assert (pipeline.folder / "patch.diff").read_bytes() == PATCH.encode()
        (pipeline.folder / "eval.json").write_text(json.dumps(evaluation))
        (pipeline.folder / "eval.log").write_text("official evaluator log")
        logs = pipeline.original.with_name("logs")
        logs.mkdir()
        (logs / "functional.junit.xml").write_text("<testsuites/>")
        if evaluation["apply_ok"]:
            candidate.mkdir()
        return SimpleNamespace(returncode=0, stdout="evaluator stdout", stderr="")

    monkeypatch.setattr(subprocess, "run", invoke)
    monkeypatch.setattr(experiment.shutil, "which", lambda _: "/mock/patch")
    monkeypatch.setattr(sys, "argv", ["run_experiment.py", "--case", CASE])
    experiment.main()

    row = read_record(pipeline)
    fields = ("patch_applied", "functional_test_pass", "security_test_pass",
              "verified_repair", "false_assurance")
    assert tuple(row[field] for field in fields) == expected
    evidence = pipeline.results / "evidence" / CASE
    assert (evidence / "eval.log").read_text() == "official evaluator log"
    assert (evidence / "scan_report.tsv").is_file()
    assert (evidence / "benchmark_logs" / "functional.junit.xml").is_file()
    if expected[0] is None:
        assert row["error_type"] == "IncompleteOracleResults"
        assert len(calls) == 1
    else:
        assert row["semgrep_findings_before"] == 1
        assert (evidence / "semgrep" / "semgrep_before.log").read_text() == "scan log"
        if expected[0]:
            assert row["semgrep_findings_after"] == 0
            assert (evidence / "semgrep" / "semgrep_after.json").is_file()
            assert len(calls) == 3
        else:
            assert row["semgrep_findings_after"] is None
            assert len(calls) == 2
    pipeline.request.assert_called_once()


def test_attempt_reservation_blocks_second_generation(pipeline):
    experiment.generate(pipeline.folder, "example")
    manifest = (pipeline.folder / "frozen.json").read_bytes()
    with pytest.raises(FileExistsError):
        experiment.generate(pipeline.folder, "second request")
    pipeline.request.assert_called_once()
    assert (pipeline.folder / "frozen.json").read_bytes() == manifest

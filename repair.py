import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from openai import OpenAI

ROOT = Path(__file__).resolve().parent
BENCH = ROOT / "vul4py"
sys.path.insert(0, str(BENCH / "scripts"))
from run_agent import collect_context_files

MODEL = "gpt-6-luna"

PROMPT = """You are given vulnerable Python source code from a real software project.
Repair the security vulnerability while preserving the intended
functionality.
You have only one repair attempt.
Return a unified diff patch that can be applied to the original project.
Also report:
1. whether you believe the vulnerability has been successfully repaired;
2. your confidence in that assessment as a number between 0.0 and 1.0.
Do not assume access to external verification results."""

SCHEMA = {
    "type": "object",
    "properties": {
        "claimed_success": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "patch": {"type": "string"},
    },
    "required": ["claimed_success", "confidence", "patch"],
    "additionalProperties": False,
}


def save_json(path, data):
    with path.open("x", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def generate(case_id, student_id, client):
    case = BENCH / "workspaces" / case_id
    run = BENCH / "runs" / "student" / case_id

    if run.exists():
        print(case_id, "OMITIDO: ya existe un intento.")
        return

    meta = json.loads((case / "meta.json").read_text())
    files = collect_context_files(case, meta, max_files=20, max_bytes=200000)
    if not files:
        print(case_id, "ERROR: no se encontró código para enviar.")
        return

    blocks = [f"Vulnerability ID: {case_id}"]
    for relative, source in files:
        blocks.append(f"\nFILE: {relative}\n{source}")
    source_input = "\n".join(blocks)

    run.mkdir(parents=True, exist_ok=False)
    save_json(run / "request.json", {
        "model": MODEL,
        "instructions": PROMPT,
        "input": source_input,
        "source_files": [name for name, _ in files],
    })

    record = {
        "student_id": student_id,
        "case_id": case_id,
        "model": MODEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api_success": False,
        "error_type": "",
        "input_tokens": None,
        "output_tokens": None,
        "latency_ms": None,
    }

    start = time.perf_counter()
    try:
        response = client.responses.create(
            model=MODEL,
            instructions=PROMPT,
            input=source_input,
            max_output_tokens=12000,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "repair_assessment",
                    "strict": True,
                    "schema": SCHEMA,
                }
            },
        )
        record["latency_ms"] = (time.perf_counter() - start) * 1000
        record["api_success"] = True

        # Guardar la respuesta original antes de analizarla o evaluar.
        save_json(run / "llm_response.json", response.model_dump(mode="json"))
        if response.usage:
            record["input_tokens"] = response.usage.input_tokens
            record["output_tokens"] = response.usage.output_tokens

        if response.status != "completed":
            raise ValueError("Respuesta incompleta")

        assessment = json.loads(response.output_text)
        assert type(assessment["claimed_success"]) is bool
        assert type(assessment["confidence"]) in (int, float)
        assert 0 <= assessment["confidence"] <= 1
        assert isinstance(assessment["patch"], str)

        save_json(run / "assessment.json", assessment)
        patch_bytes = assessment["patch"].encode("utf-8")
        with (run / "patch.diff").open("xb") as f:
            f.write(patch_bytes)

        record["patch_sha256"] = hashlib.sha256(patch_bytes).hexdigest()
        print(case_id, "RESPUESTA GUARDADA",
              "claim=", assessment["claimed_success"],
              "confidence=", assessment["confidence"])
    except Exception as error:
        if record["latency_ms"] is None:
            record["latency_ms"] = (time.perf_counter() - start) * 1000
        record["error_type"] = type(error).__name__
        record["http_status"] = getattr(error, "status_code", None)
        print(case_id, "ERROR:", record["error_type"],
              "HTTP:", record["http_status"])
    finally:
        save_json(run / "generation.json", record)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", nargs="+", required=True)
    parser.add_argument("--student-id", required=True)
    args = parser.parse_args()

    import csv
    with (BENCH / "workspaces" / "scan_report.tsv").open() as f:
        valid = {
            row["cve_id"]
            for row in csv.DictReader(f, delimiter="\t")
            if row["status"] == "OK"
        }
    if not set(args.cases) <= valid:
        parser.error("Solo se permiten casos con validación OK.")
    if not os.environ.get("OPENAI_API_KEY"):
        parser.error("Falta OPENAI_API_KEY.")

    client = OpenAI(max_retries=0, timeout=180)
    for case_id in args.cases:
        generate(case_id, args.student_id, client)


if __name__ == "__main__":
    main()

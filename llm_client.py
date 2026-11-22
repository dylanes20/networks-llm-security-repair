"""Make one Responses API request and validate the experimental envelope."""
import json
import os
import time
from pathlib import Path

from config import MODEL, PROMPT
from models import LLMResult


def write_json(path: Path, data) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)


def repair(vulnerable_source: str, *, folder: Path) -> LLMResult:
    from openai import OpenAI

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], max_retries=0, timeout=180)
    request = {
        "model": MODEL,
        "input": PROMPT + "\n\nVulnerable source:\n" + vulnerable_source,
        "text": {"format": {"type": "json_schema", "name": "repair", "strict": True,
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "claimed_success": {"type": "boolean"},
                                    "confidence": {"type": "number"},
                                    "patch": {"type": "string"},
                                },
                                "required": ["claimed_success", "confidence", "patch"],
                                "additionalProperties": False,
                            }}},
    }
    write_json(folder / "request.json", request)
    generation = json.loads((folder / "attempt.json").read_text())
    start = time.perf_counter()
    try:
        response = client.responses.create(**request)
    except Exception:
        generation["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
        write_json(folder / "generation.json", generation)
        raise
    generation.update(
        latency_ms=round((time.perf_counter() - start) * 1000, 1),
        input_tokens=getattr(response.usage, "input_tokens", None),
        output_tokens=getattr(response.usage, "output_tokens", None),
    )
    write_json(folder / "api_response.json", response.model_dump(mode="json"))
    write_json(folder / "generation.json", generation)
    raw = response.output_text
    (folder / "raw_response.txt").write_bytes(raw.encode("utf-8"))
    if response.status != "completed":
        raise ValueError("Incomplete model response")
    data = json.loads(raw)
    if not isinstance(data, dict) or type(data.get("claimed_success")) is not bool:
        raise ValueError("Invalid repair claim")
    confidence = data.get("confidence")
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        raise ValueError("Invalid confidence")
    patch = data.get("patch")
    if not isinstance(patch, str) or not patch.strip():
        raise ValueError("Missing patch")
    return LLMResult(data["claimed_success"], confidence, patch, raw,
                     generation["latency_ms"], generation["input_tokens"],
                     generation["output_tokens"])

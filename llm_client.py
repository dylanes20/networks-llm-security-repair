import json
import os
import time

from openai import OpenAI

from config import MODEL, PROMPT
from models import LLMResult


RESPONSE_FORMAT = {
    "type": "json_schema",
    "name": "repair_result",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "claimed_success": {"type": "boolean"},
            "confidence": {"type": "number"},
            "patch": {"type": "string"},
        },
        "required": ["claimed_success", "confidence", "patch"],
        "additionalProperties": False,
    },
}


def repair(vulnerable_source: str) -> LLMResult:
    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY"],
        max_retries=0,
        timeout=180,
    )

    start = time.perf_counter()
    response = client.responses.create(
        model=MODEL,
        input=PROMPT + "\n\nVulnerable source:\n" + vulnerable_source,
        text={"format": RESPONSE_FORMAT},
    )
    latency_ms = (time.perf_counter() - start) * 1000
    raw = response.output_text

    try:
        if response.status != "completed":
            raise ValueError("Incomplete response")

        data = json.loads(raw)

        if type(data["claimed_success"]) is not bool:
            raise ValueError("claimed_success must be a boolean")

        confidence = data["confidence"]
        if type(confidence) not in (int, float):
            raise ValueError("confidence must be a number")
        if not 0 <= confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

        if not isinstance(data["patch"], str):
            raise ValueError("patch must be a string")

    except (ValueError, KeyError, TypeError) as error:
        error.raw_response = raw
        error.latency_ms = latency_ms
        raise

    usage = response.usage

    return LLMResult(
        claimed_success=data["claimed_success"],
        confidence=float(confidence),
        patch=data["patch"],
        raw_response=raw,
        latency_ms=latency_ms,
        input_tokens=usage.input_tokens if usage else None,
        output_tokens=usage.output_tokens if usage else None,
    )

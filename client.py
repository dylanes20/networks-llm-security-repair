import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from openai import OpenAI
from config import MODEL, PROMPT
from source import serialize_project


# Cambia únicamente este identificador para seleccionar otro caso.
CASE_ID = "CVE-2021-32839"

PROJECT = Path("vul4py/workspaces") / CASE_ID / "vulnerable"
OUTPUT = Path("runs/final/student") / CASE_ID


def save_json(path, data):
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def freeze_evidence(folder):
    """Guarda las huellas de los archivos antes de la evaluación."""
    names = (
        "request.json",
        "api_response.json",
        "raw_response.txt",
        "llm_response.json",
        "patch.diff",
        "generation.json",
    )

    hashes = {}

    for name in names:
        path = folder / name
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        path.chmod(0o444)

    save_json(folder / "frozen.json", hashes)
    (folder / "frozen.json").chmod(0o444)


def main():
    # La clave se obtiene de la variable de entorno.
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()

    if not api_key:
        raise ValueError("Configura la variable OPENAI_API_KEY.")

    if not PROJECT.is_dir():
        raise FileNotFoundError(f"No existe el proyecto: {PROJECT}")

    # Evita repetir una solicitud o sobrescribir sus resultados.
    if OUTPUT.exists():
        raise FileExistsError(
            f"El caso ya tiene una ejecución guardada: {OUTPUT}"
        )

    source = serialize_project(PROJECT)

    if not source.strip():
        raise ValueError("No se encontraron archivos de código.")

    client = OpenAI(
        api_key=api_key,
        max_retries=0,
        timeout=180,
    )

    messages = [
        {
            "role": "system",
            "content": PROMPT,
        },
        {
            "role": "user",
            "content": (
                "Response envelope: a JSON object with "
                "claimed_success (boolean), confidence (0-1), "
                "and patch (string).\n\n"
                "Vulnerable source:\n" + source
            ),
        },
    ]

    OUTPUT.mkdir(parents=True, exist_ok=False)

    save_json(
        OUTPUT / "request.json",
        {"model": MODEL, "messages": messages},
    )

    metadata = {
        "model": MODEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": None,
        "input_tokens": None,
        "output_tokens": None,
    }

    print("Enviando el caso a OpenAI:", CASE_ID)
    start = time.perf_counter()

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            response_format={"type": "json_object"},
        )
    except Exception as error:
        metadata["latency_ms"] = round(
            (time.perf_counter() - start) * 1000, 1
        )

        save_json(OUTPUT / "generation.json", metadata)
        save_json(
            OUTPUT / "error.json",
            {
                "phase": "api",
                "error_type": type(error).__name__,
                "http_status": getattr(error, "status_code", None),
            },
        )

        print("Error de API:", type(error).__name__)
        print("Evidencia guardada en:", OUTPUT)
        return

    metadata["latency_ms"] = round(
        (time.perf_counter() - start) * 1000, 1
    )

    if response.usage:
        metadata["input_tokens"] = response.usage.prompt_tokens
        metadata["output_tokens"] = response.usage.completion_tokens

    save_json(OUTPUT / "generation.json", metadata)

    (OUTPUT / "api_response.json").write_text(
        response.model_dump_json(indent=2),
        encoding="utf-8",
    )

    choice = response.choices[0]
    raw = choice.message.content or ""

    (OUTPUT / "raw_response.txt").write_text(
        raw,
        encoding="utf-8",
    )

    try:
        if choice.finish_reason != "stop":
            raise ValueError("La respuesta quedó incompleta.")

        if choice.message.refusal:
            raise ValueError("El modelo rechazó la solicitud.")

        data = json.loads(raw)

        if not isinstance(data, dict):
            raise ValueError("La respuesta debe ser un objeto JSON.")

        claim = data.get("claimed_success")
        confidence = data.get("confidence")
        patch = data.get("patch")

        if type(claim) is not bool:
            raise ValueError("claimed_success debe ser booleano.")

        if (
            type(confidence) not in (int, float)
            or not 0 <= confidence <= 1
        ):
            raise ValueError("confidence debe estar entre 0 y 1.")

        if not isinstance(patch, str) or not patch.strip():
            raise ValueError("El parche está vacío o no es texto.")

    except (ValueError, TypeError) as error:
        save_json(
            OUTPUT / "parse_error.json",
            {"phase": "parsing", "error": str(error)},
        )
        print("Respuesta inválida:", error)
        print("Respuesta original guardada en:", OUTPUT)
        return

    save_json(
        OUTPUT / "llm_response.json",
        {
            "claimed_success": claim,
            "confidence": confidence,
            "patch": patch,
            "raw_response": raw,
        },
    )

    # Guarda el parche exactamente como lo entregó el modelo.
    (OUTPUT / "patch.diff").write_text(patch, encoding="utf-8")

    freeze_evidence(OUTPUT)

    print("Respuesta y parche guardados.")
    print("Caso:", CASE_ID)
    print("Éxito declarado:", claim)
    print("Confianza:", confidence)
    print("Latencia (ms):", metadata["latency_ms"])
    print("Tokens de entrada:", metadata["input_tokens"])
    print("Tokens de salida:", metadata["output_tokens"])
    print("Carpeta:", OUTPUT)
    print("La aplicación del parche y las pruebas quedan pendientes.")


if __name__ == "__main__":
    main()
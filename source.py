def serialize_project(project_dir):
    excluded = {
        ".venv",
        "venv",
        ".git",
        "__pycache__",
        "backported_tests",
        "backported_support",
    }

    parts = []
    for path in sorted(project_dir.rglob("*.py")):
        relative = path.relative_to(project_dir)

        if any(part in excluded for part in relative.parts):
            continue

        parts.append(
            f"\n--- {relative} ---\n"
            f"{path.read_text(encoding='utf-8')}"
        )

    return "".join(parts)

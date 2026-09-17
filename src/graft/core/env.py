import os
from pathlib import Path


def load_env_file(path: Path | str | None = None) -> dict[str, str]:
    target = Path(path) if path is not None else Path(".env")
    if not target.is_file():
        return {}

    loaded: dict[str, str] = {}
    try:
        content = target.read_text(encoding="utf-8")
    except OSError:
        return {}

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        if "=" not in line:
            continue

        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()

        # Strip enclosing single or double quotes
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            val = val[1:-1]

        if key and key not in os.environ:
            os.environ[key] = val
            loaded[key] = val

    return loaded

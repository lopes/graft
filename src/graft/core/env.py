import os
from pathlib import Path

_DEFAULT_ENGINES_DIR = Path(__file__).resolve().parent.parent / "engines"


def _load_single_env_file(target: Path, loaded: dict[str, str]) -> None:
    if not target.is_file():
        return

    try:
        content = target.read_text(encoding="utf-8")
    except OSError:
        return

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

        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            val = val[1:-1]

        if key and key not in os.environ:
            os.environ[key] = val
            loaded[key] = val


def load_env_file(
    path: Path | str | None = None,
    engines_dir: Path | str | None = None,
) -> dict[str, str]:
    loaded: dict[str, str] = {}
    if path is not None:
        _load_single_env_file(Path(path), loaded)
        return loaded

    _load_single_env_file(Path(".env"), loaded)

    resolved_engines_dir = Path(engines_dir) if engines_dir is not None else _DEFAULT_ENGINES_DIR
    if resolved_engines_dir.is_dir():
        for child in sorted(resolved_engines_dir.iterdir()):
            if child.is_dir() and not child.name.startswith("_"):
                _load_single_env_file(child / ".env", loaded)

    return loaded

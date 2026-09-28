import re
from pathlib import Path

FORBIDDEN_PATTERNS = (
    "/usr/local/google",
    "joelopes",
    "googlers.com",
    "@google.com",
)

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "build",
}

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
FENCED_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)


def _tracked_files() -> list[Path]:
    root = Path(".")
    files: list[Path] = []
    for p in sorted(root.rglob("*")):
        if any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in p.parts):
            continue
        if p.is_file():
            files.append(p)
    return files


def test_no_workstation_paths_or_corporate_identifiers_in_tracked_files() -> None:
    self_rel = Path("tests/unit/core/test_documentation_integrity.py")
    violations: list[str] = []
    for path in _tracked_files():
        if not path.is_file() or path == self_rel:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for pattern in FORBIDDEN_PATTERNS:
            if pattern in content:
                violations.append(f"{path}: contains forbidden pattern '{pattern}'")

        if path.suffix == ".md" and "file:///" in content:
            violations.append(f"{path}: contains local 'file:///' URI")

    assert not violations, "Sensitive or local path leaks detected:\n" + "\n".join(violations)


def test_markdown_relative_links_resolve() -> None:
    broken_links: list[str] = []
    md_files = [p for p in _tracked_files() if p.suffix == ".md" and p.is_file()]

    for md_path in md_files:
        raw_content = md_path.read_text(encoding="utf-8")
        stripped_content = FENCED_BLOCK_RE.sub("", raw_content)

        for match in MARKDOWN_LINK_RE.finditer(stripped_content):
            target = match.group(1).strip()
            if not target or target.startswith(("#", "http://", "https://", "mailto:", "file://")):
                continue

            rel_path_str = target.split("#", 1)[0]
            if not rel_path_str:
                continue

            resolved = (md_path.parent / rel_path_str).resolve()
            if not resolved.exists():
                broken_links.append(f"{md_path}: broken relative link '{target}'")

    assert not broken_links, "Broken Markdown relative links:\n" + "\n".join(broken_links)


def test_governance_and_release_files_complete() -> None:
    for required_file in (
        "README.md",
        "LICENSE",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "CHANGELOG.md",
    ):
        assert Path(required_file).is_file(), f"Missing required governance file: {required_file}"

    license_text = Path("LICENSE").read_text(encoding="utf-8")
    assert "[yyyy] [name of copyright owner]" not in license_text


def test_core_and_cli_have_no_hardcoded_secops_coupled_branches() -> None:
    for core_py in sorted(Path("src/graft/core").rglob("*.py")):
        content = core_py.read_text(encoding="utf-8")
        assert "secops" not in content.lower(), (
            f"Driving Core file {core_py} contains engine-specific 'secops' reference"
        )

    commands_core = Path("src/graft/cli/commands_core.py").read_text(encoding="utf-8")
    assert 'engine = "secops"' not in commands_core, (
        "commands_core.py must not hardcode engine = 'secops' fallback"
    )
    engine_controller = Path("src/graft/cli/engine_controller.py").read_text(encoding="utf-8")
    assert "adapter: Any" not in engine_controller, (
        "engine_controller.py must type adapter as EngineAdapter, not Any"
    )

# Contributing to Graft

Thank you for contributing to Graft. Graft is an extensible, standards-aligned Detection-as-Code (DaC) platform built on hexagonal architecture and strict standard library principles.

---

## Code of Conduct & Philosophy

- **Stdlib-First Policy:** Solve problems using Python standard libraries first. Zero third-party runtime dependencies are accepted beyond `pyyaml` (YAML I/O) and `jsonschema` (Draft 2020-12 validation). HTTP clients, subprocess callers, CLI parsers, and data models must rely on stdlib.
- **Hexagonal Architecture:** The core engine (`src/graft/core/`) must remain 100% agnostic to cloud providers, SIEM APIs, and HTTP transports. All SIEM-specific interactions must live in engine adapters (`src/graft/engines/<engine>/`).
- **High Signal-to-Noise:** Comments must explain *why* or non-obvious security/API constraints, never restate what the code does. Commented-out dead code and promotional trailers are rejected.
- **Strict TDD:** Tests are written first (Red-Green-Refactor). Unit tests must execute in <1s with 100% mock isolation.

---

## Development Setup

### Prerequisites
- Python >= 3.13
- [uv](https://docs.astral.sh/uv/)

```bash
# Clone the repository
git clone https://github.com/lopes/graft.git
cd graft

# Sync development environment
uv sync
```

---

## Quality Gates & Verification

Before submitting any Pull Request, ensure all quality gates pass cleanly:

```bash
# 1. Linting with Ruff
uv run ruff check .

# 2. Code formatting check
uv run ruff format --check .

# 3. Strict type checking
uv run mypy --strict src tests

# 4. Offline test execution
uv run pytest tests/unit tests/engines

# 5. Offline rule & manifest linting
uv run graft lint
```

---

## Commit Message Convention

Graft enforces [Scoped Commits](https://scopedcommits.com/):

```
<scope>: <description>
```

- **Scope:** Lowercase component or subsystem (e.g., `secops`, `core`, `cli`, `rules`, `docs`, `ci`). For multi-area changes, use comma-separated scopes (`core,cli: ...`); for repo-wide changes, use `treewide`.
- **Description:** One-sentence imperative summary starting with a lowercase letter, without a trailing period.
- **Banned prefixes:** Generic prefixes like `feat:`, `fix:`, `chore:`, `update:` are prohibited.

### Examples:
- `secops: implement chronicle v1alpha client and verifyRuleText compiler adapter`
- `core,cli: implement mitre matrix navigator export and git-attributed rule catalog`
- `docs: add comprehensive documentation suite, architecture diagrams, and toc`

---

## Pull Request Workflow

1. Fork or branch from `main`.
2. Implement your changes following Test-Driven Development (Red-Green-Refactor).
3. Verify all five quality gates pass with zero warnings or errors.
4. Commit using Scoped Commits.
5. Open a Pull Request against `main`. All CI checks must pass before review and merge.

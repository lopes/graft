## Description
<!-- Provide a brief, high-level summary of your changes. Explain WHY rather than WHAT. -->

## Related Issue / Context
<!-- Link to issue, research link, or relevant ticket (e.g. Closes #12, Ref https://...) -->

## Type of Change
- [ ] Detection Rule (`rules/`)
- [ ] Core Engine / Schemas (`src/graft/core/`)
- [ ] Engine Adapter (`src/graft/engines/`)
- [ ] CLI Subsystem (`src/graft/cli/`)
- [ ] Documentation (`docs/`)
- [ ] CI/CD & Governance (`.github/`)

## Quality Checklist
- [ ] Rule schemas validated cleanly (`graft lint`).
- [ ] MITRE ATT&CK mappings validated against current enterprise matrix.
- [ ] Offline unit test suite passes cleanly in <1s (`uv run pytest`).
- [ ] Strict type checking passes with zero errors (`uv run mypy --strict src tests`).
- [ ] Linter & formatter pass with zero warnings (`uv run ruff check .` and `uv run ruff format --check .`).
- [ ] Commit follows Scoped Commits convention (`<scope>: <description>`).
- [ ] No unapproved third-party runtime dependencies introduced (preserving stdlib-first architecture).

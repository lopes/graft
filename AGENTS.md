# AGENTS.md: Engineering Rules & Operational Directives for Graft

> **Authoritative Operational Directives for AI Agents & Engineers**  
> **Repository:** `graft` | **Platform:** Extensible Detection-as-Code Platform  
> **Target Python:** >= 3.13 | **Package Manager:** `uv` (Native `uv_build`)  
> **Engineering Discipline:** Strict TDD, Hexagonal Architecture, Stdlib-First, High Signal-to-Noise

---

## 1. Core Operating Principles

1. **Direct, Grounded & Brutally Honest:**
   - No sycophancy, no conversational fluff, no false consensus. If an architectural approach or implementation has flaws, point them out upfront.
   - Prefer boring, stable, and simple solutions. Push back on contortions, hacks, and unnecessary abstractions.
2. **Root Cause First:**
   - Investigate before modifying code. Identify verified root causes before proposing patches.
   - Never suppress linter warnings, broad `try/except`, disable tests, or paper over race conditions.
3. **Phased Execution:**
   - For non-trivial tasks (multi-file, new engines, refactors), present an explicit phase breakdown before starting. Each phase must be a coherent, reviewable unit.
   - Never implement code belonging to future phases. Stop at phase boundaries, report completion, and wait for user confirmation before proceeding.

---

## 2. Architecture & Structural Boundaries

- **Hexagonal Architecture (Ports & Adapters):**
  - **`src/graft/core/` (Driving Core):** 100% engine-agnostic. Contains domain models, port interfaces (`typing.Protocol`), base schema validation, STIX MITRE evaluation, Git blame extraction, and exporters. **Zero imports of cloud SDKs, SIEM libraries, or HTTP clients.**
  - **`src/graft/engines/` (Driven Adapters):** Concrete engine implementations (e.g., `src/graft/engines/secops/`). **Engines carry the entire burden** of translating external SIEM APIs, authenticating, compiling queries, and handling synthetic replay vectors. Core never adapts to an engine; engines adapt to Core.
  - **`src/graft/cli/` (Driving Adapter):** Standard library `argparse` CLI routing commands to core services and engine adapters.
- **Ruleset & Dataset Taxonomy:**
  - `datasets/<name>.yaml`: Engine-agnostic 2-block YAML envelopes (`metadata`, `values`) defining reusable 1-D string lists (`0..1,000` unique non-empty strings, `maxLength: 256`, with optional inline `# ... ttl:YYYY-MM-DD` UTC expiration comments omitted when `today_utc > ttl_date`), validated against `src/graft/core/schemas/base_dataset.schema.json`. Filename stem `<name>` must strictly match `metadata.name` (`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`, `1..64` chars, `"index"` reserved) and follow the plural noun phrase convention (`<context>_<entity_plural>`, e.g., `known_scanner_ips`). Synchronized to engines supporting `datasets: true` (e.g., Google SecOps Data Tables as a single `STRING` column named `value`) via additive coexistence (unmanaged SIEM tables are never flagged as untracked or deleted; active datasets deleted remotely are recreated on sync).
  - `datasets/_archived/`: Standardized directory for decommissioned datasets. Excluded from local `graft lint` validation; during `diff/apply`, if an archived dataset still exists on the SIEM with non-empty rows or a description other than `"Deprecated on Graft"`, Graft logs an `INFO` notice, clears its remote rows to `()`, and sets its remote description to `"Deprecated on Graft"`.
  - `rulesets/<engine>/custom/`: 5-block envelope YAML files (`metadata`, `logic`, `deployment`, `runbook`, `tests`) authored and owned by the organization, validated against `src/graft/engines/<engine>/schemas/custom.schema.json` (extending `base_custom.schema.json`). `graft lint` cross-checks `%<name>` references in custom rule logic against local `datasets/<name>.yaml` (enforcing `.value` column access and literal string `in %<name>.value` membership).
  - `rulesets/<engine>/managed/index.yaml`: Single consolidated manifest tracking vendor-managed content state (e.g., Google Curated Rule Sets: `PRECISE` vs `BROAD` deployments, `enabled`, `alerting`) and active exclusions, validated against `src/graft/engines/<engine>/schemas/managed.schema.json`. Engine adapters must expose a unique `id` per managed rule/ruleset entry in `index.yaml`.
  - `rulesets/<engine>/managed/<rule_name>.yaml`: Optional 4-block registered managed rule envelopes (`metadata`, `managed`, `runbook`, `tests`) validated against `base_managed.schema.json` so vendor-managed coverage is included in MITRE ATT&CK matrices and catalogs. `graft lint` enforces that `managed.id` exists in `managed/index.yaml` and does not overlap across files (strict 1-to-1 mapping).
  - `rulesets/<engine>/_archived/`: Standardized directory for decommissioned rules. Any folder or file prefix starting with an underscore (`_`) under a ruleset is excluded from loading, linting, matrix exports, and sync operations.
- **Environment Topologies:**
  - All SecOps credentials and tenant coordinates are split into Staging and Production according to `src/graft/engines/secops/docs/README.md` (with engine-scoped `.env` templates under `src/graft/engines/<engine>/.env.example`).
- **Three-Epoch Engine Lifecycle & Ingestion Protocol:**
  - **Epoch 1 (Discovery & Reverse Sync):** When bootstrapping an existing SIEM tenant, the SIEM is the temporary initial Source of Truth. Run `graft <engine> pull` to extract live custom rules and managed curated configurations into local YAML artifacts (and optionally `graft <engine> pull --target datasets` to import compatible 1-column `STRING` tables).
  - **Epoch 2 (Baseline Enrichment & Validation):** Operators document runbooks, map MITRE ATT&CK techniques, add test vectors, validate via `graft lint`, and commit the baseline to Git.
  - **Epoch 3 (Steady-State GitOps):** Git is declared the authoritative Source of Truth. `graft <engine> diff/apply` synchronizes changes forward in strict dependency order (**1. Datasets $\rightarrow$ 2. Custom Rules $\rightarrow$ 3. Managed Content**). Mode B (default) evaluates scoped branch changes; Mode A (`--all`) enforces full catalog convergence, healing out-of-band console drift.
- **Logging & Operational Diagnostics Contract:**
  - Root CLI logging uses ISO-8601 UTC timestamps (`%(asctime)s [%(levelname)s] %(message)s` with `datefmt="%Y-%m-%dT%H:%M:%SZ"` and `logging.Formatter.converter = time.gmtime`).
  - Core reconcilers (`graft.reconciler`) own `INFO` CRUD lifecycle logs, `ERROR` failure context (`Failed <action> '<name>': <error>`), and partial-progress batch abort summaries (`X/Y applied [...], 1 failed [...], Z pending [...]`).
  - Driven adapters (`graft.<engine>.*`) must not emit duplicate `INFO` CRUD logs; they emit `DEBUG` sub-step traces, `WARNING` logs on transient HTTP retry backoffs (`429`/`503`) or two-stage partial mutations, and format API exceptions with HTTP status code, vendor status, method, and endpoint path.

---

## 3. Technology Stack & Strict Stdlib-First Policy

- **Runtime Environment:** Python >= 3.13. Native `uv_build` backend. Managed strictly via `uv`.
- **Build System:** `[build-system]` uses `build-backend = "uv_build"`. `hatchling` is strictly prohibited.
- **Strict Stdlib-First Rule:**
  - Solve problems using Python standard libraries first.
  - **Zero third-party runtime dependencies allowed**, except:
    1. `pyyaml` (or `ruamel.yaml`): For YAML parsing/emission (Python stdlib lacks YAML support).
    2. `jsonschema`: For Draft 2020-12 schema validation.
  - All other capabilities must use stdlib:
    - HTTP requests: `urllib.request`, `urllib.error` (No `requests`, no `httpx`).
    - CLI routing: `argparse` (No `click`, no `typer`).
    - Domain models: `dataclasses` (No `pydantic` in core).
    - Subprocess / Git: `subprocess`.
    - CSV generation: `csv`.
    - Hashing / UUID: `hashlib`, `uuid`.
- **Development / Test Dependencies (Dev-Group Only):**
  - `pytest`, `pytest-cov`: Test harness.
  - `mypy`: Strict static type checking (`mypy --strict`).
  - `ruff`: Linter and formatter.
  - Dev dependencies are isolated to `[dependency-groups.dev]` and must never be imported in production source code (`src/graft/`).

---

## 4. Code Commenting Directives (High Signal-to-Noise)

- **Only add comments when strictly necessary to explain *why*, non-obvious constraints, or security rationale.**
- **Strictly Banned:**
  - Zero obvious comments (e.g., `# set name to rule name`, `# loop over rules`, `# return the result`).
  - Zero boilerplate function headers repeating type signatures or parameter lists already captured by type hints.
  - Zero commented-out dead code. Delete dead code immediately.
  - Zero promotional trailers or LLM signatures (`# Generated by...`, `# Created with AI`).

---

## 5. Documentation, Markdown & Diagram Directives

- **Markdown List Style:** All unordered markdown lists must strictly use hyphens (`-`), never asterisks (`*`).
- **Mermaid Everywhere:** All architectural diagrams, workflows, execution sequences, state machines, and system topologies in documentation must be expressed using standard GitHub Markdown Mermaid fenced code blocks (` ```mermaid `).
- **Strictly Banned:**
  - Zero ASCII art box-drawing diagrams in markdown documentation.
  - Zero static binary images for architectural or procedural flows where Mermaid can represent the structure.
- **Mermaid Syntax Standards:**
  - Always quote node labels containing special characters, parentheses, brackets, or code tags (e.g., `ID["Label (Detail)"]`).
  - Use directed flowcharts (`flowchart TD` or `flowchart LR`) with clean semantic naming.

---

## 6. Test-Driven Development (TDD) Conventions

- **Mandatory Red-Green-Refactor:**
  1. **Red:** Write the failing test first in `tests/`. Run pytest and verify it fails for the expected reason.
  2. **Green:** Write the minimum code required in `src/graft/` to pass the test.
  3. **Refactor:** Clean up code, enforce strict types, and ensure all linter rules pass.
- **Partitioned Test Hierarchy:**
  - `tests/unit/`: 100% mock-isolated, sub-second execution (<1s total). Never makes real network or disk calls outside temp directories.
  - `tests/engines/`: Mock-transport contract tests verifying API payload encoding/decoding.
  - `tests/integration/`: Live API tests targeting the dedicated staging tenant, strictly gated behind `@pytest.mark.integration` and `--run-integration`.
- **Graceful Degradation for Replay Tests:**
  - If a rule defines a `test:` block, but staging credentials (`GRAFT_STAGING_*`) are absent: emit `[WARNING]` and exit with code `0`. Never block developers locally.
  - Enforce exit code `1` only when `--require-staging` is explicitly supplied.

---

## 7. Static Analysis & Verification Quality Gates

Before declaring any work complete, the following checks must return 0 errors:
1. `uv run ruff check .` — Strict rules: `E, F, B, I, UP, S, RUF, SIM, T20`. Stray `print()` calls in production source are strictly prohibited.
2. `uv run ruff format --check .` — Enforces consistent code formatting.
3. `uv run mypy --strict src tests` — Zero untyped definitions, zero implicit optionals, zero `Any`.
4. `uv run pytest tests/unit tests/engines` — 100% passing tests in <1 second.

---

## 8. Version Control, Branching, Scoped Commits & Remote Push

- **Always Work in a Feature Branch (Never Commit Directly to `main`):**
  - Before making any code, rule, or documentation modifications, create or switch to a dedicated feature branch (`git checkout -b <branch-name>`).
  - Working in branches isolates changes from `main` for safe experimentation and trivial rollback, ensures every change goes through a Pull Request so pre-merge quality and cloud verification gates (`pr-validation.yml`) run before merging to `main`, and continuously exercises our CI/CD workflows.
- Follow [Scoped Commits](https://scopedcommits.com/): `<scope>: <description>`
  - Scope first, lowercase, one-sentence imperative description.
  - Commit frequently during the phase as logical increments pass tests.
  - Banned prefixes: `feat:`, `fix:`, `chore:`, `update:`.
- **CI Workflow Path Filtering:**
  - Mainline deployment (`deploy-production.yml`, triggered on push to `main` and daily at `0 0 * * *` UTC) and PR validation (`pr-validation.yml`) enforce strict path filters (`src/**`, `datasets/**`, `rulesets/**`, `tests/**`, `pyproject.toml`, `uv.lock`, `.github/dependabot.yml`, `.github/workflows/**`).
  - Changes touching exclusively documentation (`.md`, `docs/`) or visual assets (`assets/`) intentionally skip CI execution to prevent redundant runner executions.
- **Workflow Push Permission Requirements:**
  - GitHub OAuth tokens (`gh auth token`) reject pushing changes to `.github/workflows/` unless the token possesses the `workflow` scope (`gh auth refresh -s workflow`).
  - In environments where `gh` lacks `workflow` scope, pushes modifying workflow files must be executed via SSH (`git push origin <branch>`).
- **Mandatory Remote Push at Phase Completion:**
  - At the conclusion of each phase—after all quality gates pass, the progress tracker is updated, and the phase commit is created—**push changes to the remote feature branch**:
    ```bash
    git push -u origin <current-branch>
    ```
  - Never push broken tests, failing lints, or incomplete phase work.

---

## 9. Engineering & Collaboration Protocol (Gemini / Jetski)

Follow this disciplined protocol during development and maintenance sessions:

### Start-of-Session Routine (Agent Boots Up)
1. **Inspect Baseline & Branch:** Run `git status`, `git log -n 3`, and `uv run pytest` to ensure you are starting from a clean, passing baseline. Verify you are on a dedicated feature branch (or create one from `main` via `git checkout -b <branch-name>`) before modifying any files.
2. **Ground in Operational Directives:** Review `AGENTS.md` and relevant tracks in `docs/` for architecture, stdlib-first boundaries, and quality gates.
3. **Design Alignment & Scrutiny:** Present detailed structural designs, schema field names, API signatures, and data contracts to the user for review and critique. Discuss trade-offs and obtain alignment before writing any implementation code.
4. **Execute via Strict TDD:** Implement agreed changes using strict Red-Green-Refactor TDD.

### End-of-Session Routine (Session Handoff & Completion)
1. **Verify Quality Gates:** Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, and `uv run pytest`.
2. **Commit Changes:** Create a scoped commit on the feature branch following Scoped Commits: `<scope>: <description>`.
3. **Push to Remote & Open PR:** Run `git push -u origin <current-branch>` (or verify local branch commits are ready for user push and PR creation).
4. **Handoff Report:** Output a clean summary stating what was done, what files were created/modified, and verified quality gate results.

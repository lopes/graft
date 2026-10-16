# AGENTS.md: Guide for AI Agents & Contributors

Graft is an open-source, extensible Detection-as-Code (DaC) platform written in **Python >= 3.13**, managed via **`uv`** (`build-backend = "uv_build"`, never `hatchling`), and built around **Hexagonal Architecture (Ports & Adapters)**, **Strict TDD**, and a **Stdlib-First** runtime policy. **Never add, install, or import any new Python package or OS tool without explicit maintainer approval.** The Driving Core (`src/graft/core/`) is 100% engine-agnostic—it never imports cloud SDKs, SIEM clients, or HTTP transports; Driven Engine Adapters (`src/graft/engines/<engine>/`) adapt external SIEM APIs to Core port protocols. Every platform capability is drivable from the `graft` CLI with structured `--json` output for deterministic agent and CI consumption.

---

## 1. Orientation & Documentation Tracks

| Track | Hub & Primary Guides |
| :--- | :--- |
| **Architecture** | [`docs/architecture.md`](docs/architecture.md) — Hexagonal boundaries, content tracks, and GitOps lifecycle |
| **Developers** | [`docs/developers/README.md`](docs/developers/README.md) — [`framework.md`](docs/developers/framework.md) · [`extending_engines.md`](docs/developers/extending_engines.md) · [`quality_and_standards.md`](docs/developers/quality_and_standards.md) |
| **Analysts** | [`docs/analysts/README.md`](docs/analysts/README.md) — [`rule_authoring.md`](docs/analysts/rule_authoring.md) · [`recipes.md`](docs/analysts/recipes.md) · [`replay_testing.md`](docs/analysts/replay_testing.md) · [`visibility_and_matrix.md`](docs/analysts/visibility_and_matrix.md) |
| **Operators** | [`docs/operators/README.md`](docs/operators/README.md) — [`adoption.md`](docs/operators/adoption.md) · [`gitops_reconciliation.md`](docs/operators/gitops_reconciliation.md) · [`cicd_and_infrastructure.md`](docs/operators/cicd_and_infrastructure.md) · [`security.md`](docs/operators/security.md) |
| **Engines** | [`docs/engines/README.md`](docs/engines/README.md) — Co-located engine guides at `src/graft/engines/<engine>/docs/README.md` (discover via `uv run graft --json engines`) |
| **Agent Skills** | [`.agents/skills/`](.agents/skills/) — [`scaffold-rule`](.agents/skills/scaffold-rule/SKILL.md) · [`scaffold-dataset`](.agents/skills/scaffold-dataset/SKILL.md) · [`scaffold-tests`](.agents/skills/scaffold-tests/SKILL.md) · [`review-rule`](.agents/skills/review-rule/SKILL.md) · [`cti-coverage`](.agents/skills/cti-coverage/SKILL.md) |

---

## 2. Workspace & Hexagonal Architecture Map

| Path | Layer & Responsibility | Allowed Imports |
| :--- | :--- | :--- |
| [`src/graft/core/models/`](src/graft/core/models/) | **Domain Models:** Immutable `@dataclass(frozen=True)` structures (`RuleEnvelope`, `DatasetEnvelope`, `ManagedState`, `CompilationResult`). | Python stdlib and `graft.core.models` only. |
| [`src/graft/core/ports/`](src/graft/core/ports/) | **Port Contracts:** `@runtime_checkable` `typing.Protocol` interfaces (`EngineAdapter`, `DatasetPort`, `RuleCompilerPort`, `RuleDeployerPort`, `ManagedEnginePort`, `ReplayHarnessPort`). | Python stdlib, `graft.core.models`, and `graft.core.ports` only. |
| [`src/graft/core/`](src/graft/core/) | **Driving Core Services:** YAML loaders/dumpers, Draft 2020-12 `SchemaValidator`, STIX `MitreValidator`, reconcilers (`Dataset`, `CustomRule`, `GitOps`), `GitBlameExtractor`, `EngineRegistry`, and exporters. | `models`, `ports`, sibling `core` modules, stdlib, and approved runtime deps in [`pyproject.toml`](pyproject.toml). Never imports `graft.cli`, `graft.engines`, or HTTP clients (except `mitre_validator.py` for explicit STIX updates). |
| [`src/graft/engines/<engine>/`](src/graft/engines/) | **Driven Engine Adapters:** Self-contained vendor packages (`engine.yaml`, `schemas/`, `docs/README.md`, `.env.example`, REST client, compiler, deployer, dataset sync, managed sync, and replay harness). | `graft.core`, own engine package (`graft.engines.<engine>`), stdlib, and approved runtime deps. Never imports `graft.cli` or another engine adapter. |
| [`src/graft/cli/`](src/graft/cli/) | **Driving CLI Adapter:** `argparse` entry point ([`main.py`](src/graft/cli/main.py)), core handlers ([`commands_core.py`](src/graft/cli/commands_core.py)), dynamic engine router ([`engine_controller.py`](src/graft/cli/engine_controller.py)), and scaffolder ([`scaffold.py`](src/graft/cli/scaffold.py)). | `graft.core`, sibling `cli` modules, stdlib, and approved runtime deps. Never statically imports `graft.engines.<engine>.*` (routes through `EngineRegistry` and `EngineAdapter`). |
| [`datasets/`](datasets/) & [`rulesets/<engine>/`](rulesets/) | **Declarative Content:** 2-block datasets (`datasets/<name>.yaml`), 5-block custom rules (`custom/*.yaml`), vendor state (`managed/index.yaml`), 4-block managed rules (`managed/<rule>.yaml`), and `_archived/`. | Validated by [`src/graft/core/schemas/`](src/graft/core/schemas/) and `src/graft/engines/<engine>/schemas/`. |
| [`tests/`](tests/) | **Partitioned Test Suite:** `tests/unit/` (100% mock-isolated, engine-agnostic, `<1s`), `tests/engines/<engine>/` (mock-transport contract tests), and `tests/integration/` (gated by `--run-integration`). | Enforced by [`test_architecture_layers.py`](tests/unit/core/test_architecture_layers.py) and [`test_documentation_integrity.py`](tests/unit/core/test_documentation_integrity.py). |

---

## 3. Golden Rules

### 1. Never Crash on Hostile Input (Outranks Feature Work)
Malformed YAML, invalid UTF-8 bytes, missing file paths, or unexpected API payloads must produce actionable errors—never unhandled `KeyError`, `IndexError`, `AttributeError`, `TypeError`, or `UnicodeDecodeError`.
- **Typed Domain Exceptions:** Parsers in [`loader.py`](src/graft/core/loader.py), engine manifest loaders, and [`engine_registry.py`](src/graft/core/engine_registry.py) must raise `RuleLoadError`, `DatasetLoadError`, `ManagedManifestLoadError`, `EngineError`, or `ScaffoldError`.
- **Strict `--json` Error Contract:** When `--json` is passed on the CLI, every failure exit path must emit valid JSON on `stdout` (`{"success": false, "error": "..."}`) before exiting non-zero.
- **Prove It:** Every parser or CLI failure fix ships with a regression test in [`tests/unit/core/test_adversarial_inputs.py`](tests/unit/core/test_adversarial_inputs.py).

### 2. Strict Test-Driven Development (`Red -> Green -> Refactor`)
- **Red:** Before implementing a feature, bug fix, or parser change, write a failing unit test (`tests/unit/`), engine contract test (`tests/engines/<engine>/`), or adversarial test (`test_adversarial_inputs.py`).
- **Green:** Write the minimal production code in `src/graft/` required to pass the test.
- **Refactor:** Clean up duplication, enforce strict typing (`mypy --strict`), and verify architectural gates while keeping all tests green.

### 3. Every Capability Is CLI + `--json` Drivable
Trigger, inspect, and test every transformation from the CLI without writing throwaway scripts or requiring live cloud credentials:
- `uv run graft --json engines` — Introspect registered engines, capability flags, environments, and schema paths.
- `uv run graft --json lint [paths...]` — Validate datasets, custom rules, managed manifests, `%<name>.value` references, and 1-to-1 ID uniqueness offline.
- `uv run graft --json mitre coverage | gaps | inspect | update` — Analyze MITRE ATT&CK coverage, 3-state gap roll-ups (`covered`/`partial`/`uncovered`), targeted STIX enrichments (`DETxxxx`, `ANxxxx`, `DCxxxx`, `Gxxxx`, `Mxxxx`), and taxonomy updates offline.
- `uv run graft --json export datasets | catalog | navigator` — Inspect active datasets (after UTC `ttl:YYYY-MM-DD` filtering), Git-attributed catalogs, and ATT&CK Navigator layers (`matrix` / `mitre` aliases supported).
- `uv run graft --json <engine> render [paths...] [--all]` — Synthesize engine-native queries (e.g., full rule with injected metadata) completely offline.
- `uv run graft --json <engine> verify | test | diff | apply | pull` — Execute remote compilation, staging replay, and GitOps reconciliation.

### 4. Keep Schemas, Models, and Round-Trips Complete
`RuleEnvelope`, `DatasetEnvelope`, and `ManagedState` are mechanically checked against [`src/graft/core/schemas/*.schema.json`](src/graft/core/schemas/) by [`test_architecture_layers.py`](tests/unit/core/test_architecture_layers.py). When adding or changing an envelope field, update the JSON schema, frozen dataclass in `src/graft/core/models/`, YAML loader/dumper in [`loader.py`](src/graft/core/loader.py), and engine query synthesizer/deconstructor so `load -> dump -> load` and `synthesize -> deconstruct` remain lossless.

### 5. Stdlib-First & Dependency Gate
- Solve problems with Python >= 3.13 standard libraries first (`urllib.request`, `argparse`, `dataclasses`, `subprocess`, `csv`, `hashlib`, `uuid`, `tomllib`, `ast`).
- Runtime dependencies are locked in [`pyproject.toml`](pyproject.toml) and enforced by [`test_architecture_layers.py`](tests/unit/core/test_architecture_layers.py). **Never add or install any dependency or OS tool without explicit maintainer approval.** Dev tools (`pytest`, `mypy`, `ruff`) live in `[dependency-groups.dev]` and are never imported in `src/graft/`.

### 6. Content Taxonomy, GitOps Order & Code Hygiene
- **Taxonomy & Archival:** Datasets (`datasets/<name>.yaml`, 2-block, plural snake_case `<context>_<entity_plural>`, `"index"` reserved, inline `# ... ttl:YYYY-MM-DD` UTC expiry), custom rules (`rulesets/<engine>/custom/*.yaml`, 5-block), and managed content (`managed/index.yaml` + optional 4-block `managed/<rule>.yaml`). Files/folders starting with `_` (`_archived/`) are excluded from linting and exports; archived datasets clear remote rows to `()` with description `"Deprecated on Graft"`.
- **GitOps Order:** `diff` and `apply` always run in order: **1. Datasets $\rightarrow$ 2. Custom Rules $\rightarrow$ 3. Managed Content** (scoped to branch changes by default; `--all` for full catalog drift). Missing staging credentials during `graft <engine> test` emit `[WARNING]` and exit `0` unless `--require-staging` is passed.
- **Logging, Comments & Markdown:** Core reconcilers (`graft.reconciler`) own `INFO` CRUD and `ERROR` logs; engine adapters (`graft.<engine>.*`) emit `DEBUG`/`WARNING` only (`print()` is banned by Ruff `T20`). Write comments only to explain *why* or security constraints (zero obvious comments, boilerplate docstrings, or AI trailers). Use hyphens (`-`) for markdown lists and Mermaid `flowchart TD`/`LR` with quoted node labels (`ID["Label (Detail)"]`) for diagrams.

---

## 4. Checklists ("How to Add X")

- **CLI Command / Subcommand:** Register in [`main.py`](src/graft/cli/main.py) (plus `RESERVED_CORE_COMMANDS` in [`engine_registry.py`](src/graft/core/engine_registry.py)) or [`engine_controller.py`](src/graft/cli/engine_controller.py) $\rightarrow$ support `json_output: bool = False` on both success and error paths $\rightarrow$ add engine-agnostic unit tests in `tests/unit/cli/` and engine CLI tests in `tests/engines/<engine>/`.
- **Engine Adapter:** Run `uv run graft new engine <name>` $\rightarrow$ declare capabilities and env vars in `src/graft/engines/<name>/engine.yaml` $\rightarrow$ implement [`EngineAdapter`](src/graft/core/ports/engine.py) and enabled ports (including `render_rule` and `deconstruct_rule`) $\rightarrow$ add `docs/README.md`, `.env.example`, and contract tests in `tests/engines/<name>/`.
- **Envelope Field:** Update JSON schema in `src/graft/core/schemas/` $\rightarrow$ update frozen dataclass in `src/graft/core/models/` $\rightarrow$ update loader and serializer in [`loader.py`](src/graft/core/loader.py) $\rightarrow$ run `uv run pytest tests/unit/core/test_architecture_layers.py`.

---

## 5. Verification, Branching & Parallel Safety

Before completing any task or opening a PR, all five verification gates must return **0 errors**:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests
uv run pytest tests/unit tests/engines
uv run graft lint
```

- **Branching & Scoped Commits:** Never commit directly to `main` (`git checkout -b <branch-name>`). Format commits as `<scope>: <description>` (lowercase scope, imperative one-liner, no trailing period, no `feat:`/`fix:`/`chore:`/`update:`, no AI trailers). Pushes touching `.github/workflows/` require `workflow` OAuth scope or SSH.
- **Parallel Agents & Shared Files:** Isolate concurrent agents in separate worktrees/branches (`share` / `branch`). Keep edits to shared routing/loader files (`main.py`, `commands_core.py`, `engine_controller.py`, `loader.py`) small and surgical, re-reading target lines immediately before editing. Validate `pyproject.toml`, `engine.yaml`, and `*.schema.json` immediately after any edit.

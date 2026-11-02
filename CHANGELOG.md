# Changelog

All notable changes to **Graft** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Declarative Engine-Agnostic Datasets & Self-Expiring Suppressions (`datasets/<name>.yaml`):**
  - Standardized 2-block string dataset envelope (`metadata`, `values` of `0..1,000` unique literal strings) validated by `src/graft/core/schemas/base_dataset.schema.json` and scaffolded via `graft new dataset <name>`.
  - Inline UTC auto-expiration comments (`# ... ttl:YYYY-MM-DD`) evaluated automatically during dataset loading (`today_utc > ttl_date`), keeping expired entries in Git as an audit trail while removing them from downstream SIEM lookup tables during daily reconciliation.
  - Safe archival deprecation via `datasets/_archived/<name>.yaml`: clears remote rows to `0` and sets remote table description to `"Deprecated on Graft"` so active rules referencing `%<name>.value` continue compiling and running cleanly until references are retired.
  - Core `DatasetPort` protocol (`list_datasets`, `create_dataset`, `update_dataset` with strict additive coexistence and zero unmanaged deletions), `DatasetReconciler` (ordered before custom rules and managed content during `diff` and `apply`), opt-in reverse sync (`graft <engine> pull --target datasets [--out-datasets-dir DIR]`), and offline export (`graft export datasets [--format table|csv|json] [--datasets-dir DIR]`).
  - Google SecOps `SecOpsDatasetAdapter` integrating Chronicle `v1` Data Tables (`dataTables`, `dataTableRows:bulkReplace`, empty-table row clearing, `%<name>.value` cross-reference linting, `:verifyRuleText` placeholder substitution for unprovisioned local tables, and staging replay pre-synchronization).
- **Two-Tier MITRE ATT&CK Enterprise v20.0 STIX Intelligence (`graft mitre`):**
  - Pre-compiled two-tier offline STIX bundles in `src/graft/data/`: fast primary store `mitre_attack.json` (~570 KB) and lazy-loaded behavioral analytic store `mitre_analytics.json` (~2.2 MB), updated via `graft mitre update [--version VER] [--check]`.
  - `graft mitre coverage` and `graft mitre gaps` with 3-state parent/sub-technique roll-ups (`covered`, `partial`, `uncovered`) ranked by Threat Group (`Gxxxx`) prevalence, active-rule coverage filtering (excluding `disabled` rules), `--infer-scope` footprint inference, and `--platform` / `--group` / `--tactic` / `--data-component` / `--top` slicing.
  - `graft mitre inspect` for offline lookup of techniques (`Txxxx`), tactics (`TAxxxx`), Detection Strategies (`DETxxxx`), behavioral Analytics (`ANxxxx`, `log_sources`, `mutable_elements`), Data Components (`DCxxxx`), Threat Groups (`Gxxxx`), and Mitigations (`Mxxxx`).
  - Rich `--enrich` STIX columns (`platforms`, `data_components`, `mitigations`, `group_count`) in `graft export catalog` and `--enrich` / `--include-gaps` overlays in `graft export navigator`, plus automatic `revoked-by` technique upgrades during `graft <engine> pull`.
- **Offline CLI Introspection & Query Synthesis (`graft engines` & `graft <engine> render`):**
  - `graft [--json] engines` to inspect registered detection engines, capability flags, target environments, and schema paths without network access.
  - `graft [--json] <engine> render [paths...] [--all]` (`EngineAdapter.render_rule`) to synthesize engine-native rule text (including injected metadata headers) completely offline.
  - Export command aliases: `metadata` for `graft export catalog`, and `matrix` / `mitre` for `graft export navigator`.
- **Optional Vendor-Managed Rule Registration (`rulesets/<engine>/managed/<rule_name>.yaml`):**
  - Standardized 4-block managed rule envelope (`metadata`, `managed`, `runbook`, `tests`) validated by `src/graft/core/schemas/base_managed.schema.json` (`managed.id` `1..256` chars).
  - Scaffolding support via `graft <engine> new <rule_name> --managed <id>` and `graft new rule <rule_name> --engine <engine> --managed <id>`.
  - Shift-left validation in `graft lint` verifying that every registered `managed.id` exists in `rulesets/<engine>/managed/index.yaml` (`EngineAdapter.has_managed_rule_id`) and enforcing strict 1-to-1 uniqueness per engine (`RuleUniquenessValidator`).
  - Automatic inclusion of registered managed rules in MITRE ATT&CK Navigator layers (`graft export navigator`) and governance catalogs (`graft export catalog` with `rule_type="managed"` and live deployment status resolved from `managed/index.yaml`).
- **Composable AI Agent Skills Suite (`.agents/skills/`):**
  - Added five deterministic, CLI-grounded engineering skills: `scaffold-dataset`, `scaffold-rule`, `scaffold-tests`, `review-rule` (auditing both 5-block custom and 4-block managed rule envelopes), and `analyze-coverage`.
- **Mechanical Architecture, Security & Documentation Integrity Gates (`tests/unit/core/`):**
  - `test_architecture_layers.py` AST boundary gate enforcing inward Hexagonal imports, stdlib-first runtime dependencies, JSON Schema $\leftrightarrow$ frozen dataclass parity, and lossless YAML round-trips across all repository corpora.
  - `test_adversarial_inputs.py` verifying typed domain exceptions (`RuleLoadError`, `DatasetLoadError`, `ManagedManifestLoadError`, `EngineError`, `ScaffoldError`) and strict `--json` error envelopes on malformed inputs.
  - `test_documentation_integrity.py` enforcing zero workstation/corporate identifier leaks, valid relative Markdown links, co-located engine docs/templates, skill frontmatter validity, and `AGENTS.md` / track README indexing.

### Changed
- **Ruleset, Schema & Governance Alignment:**
  - Migrated engine managed state manifests from `rulesets/<engine>/managed.yaml` to `rulesets/<engine>/managed/index.yaml`.
  - Renamed `base_rule.schema.json` to `base_custom.schema.json` and engine custom rule schemas from `rule.schema.json` to `custom.schema.json` across core and engine packages for consistent `custom` / `managed` naming.
  - Updated `.githooks/pre-commit` to run both `tests/unit` and `tests/engines` completely offline (moving upstream `graft mitre update --check` to an advisory CI check).
  - Aligned all Analyst, Operator, Developer, and SecOps Engine documentation, CLI flag defaults, environment variable matrices, `CODEOWNERS`, PR/issue templates, and example outputs with codebase ground truth.

## [0.1.0] - 2026-09-28

### Added
- **Hexagonal Detection-as-Code Core (`src/graft/core/`):**
  - 5-block custom detection rule envelope (`metadata`, `logic`, `deployment`, `runbook`, `tests`) validated via JSON Schema Draft 2020-12.
  - Pluggable engine discovery (`EngineRegistry`) and capabilities-driven CLI subcommand provisioning (`EngineCommandController`).
  - Offline MITRE ATT&CK Enterprise v19.2 taxonomy validator (`graft lint`, `graft update-mitre`) with tactic-technique cross-checking.
  - Global `metadata.id` (UUID) and per-engine `metadata.name` uniqueness enforcement.
  - Zero-cost GitOps reconciliation engine (`GitOpsReconciler` and `CustomRuleReconciler`) supporting Scoped (Mode B, default) and Full Catalog (Mode A, `--all`) convergence.
  - Threat coverage and governance exporters (`graft export matrix` for ATT&CK Navigator v5.2.0 / Layer v4.5 JSON and `graft export catalog` for Git-attributed Markdown, CSV, JSON, and terminal tables).
  - Scaffolding CLI (`graft new engine <name>`, `graft new rule <name> --engine <engine>`).
- **Google SecOps (`secops`) Engine Adapter (`src/graft/engines/secops/`):**
  - Zero-dependency Chronicle REST API client (`v1` custom rules and `v1alpha` curated rulesets / `findingsRefinements`).
  - Keyless authentication supporting Google Cloud Workload Identity Federation (WIF), `GRAFT_SECOPS_TOKEN`, and `gcloud` impersonation.
  - YARA-L 2.0 compiler synthesis, semantic deconstruction (`deconstruct_yaral_rule`), and pre-merge `:verifyRuleText` dry-run validation (`graft secops verify`).
  - In-place custom rule revision updates preserving Chronicle `ru_<uuid>` identifiers and detection history (`graft secops diff`, `graft secops apply`).
  - Declarative management of Google Cloud Curated Rule Sets (`PRECISE` / `BROAD` deployments) and `findingsRefinements` exclusions via `rulesets/secops/managed.yaml`.
  - Brownfield reverse-sync ingestion (`graft secops pull`) for existing custom rules and curated rule set configurations.
  - Quarantined synthetic UDM replay test harness (`graft secops test`) with production tenant isolation guard and graceful offline degradation.
- **CI/CD & Repository Governance:**
  - Multi-gate Pull Request validation workflow (`.github/workflows/pr-validation.yml`) and mainline production deployment workflow (`.github/workflows/deploy-production.yml`).
  - Reference Google SecOps ruleset (`rulesets/secops/custom/*.yaml` and `rulesets/secops/managed.yaml`).
  - Comprehensive Analyst, Operator, Developer, and Engine documentation (`docs/`).

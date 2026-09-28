# Changelog

All notable changes to **Graft** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

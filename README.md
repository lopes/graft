<p align="center">
  <img src="assets/graft-logo.svg" alt="Graft Logo" width="160" height="160">
</p>

<h1 align="center">graft</h1>

<p align="center">
  <strong>Write Once, Defend Everywhere.</strong><br>
  <em>An extensible, vendor-agnostic Detection-as-Code (DaC) platform engineered for Google SecOps and modern enterprise security operations.</em>
</p>

<p align="center">
  <a href="docs/README.md"><img src="https://img.shields.io/badge/status-active-brightgreen.svg" alt="Status: Active"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-%3E%3D3.13-blue" alt="Python Version"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/code%20style-ruff-000000.svg" alt="Code Style: ruff"></a>
  <a href="http://mypy-lang.org/"><img src="https://img.shields.io/badge/type_checked-mypy-informational" alt="Type Checked: mypy"></a>
</p>

> [!WARNING]
> **Public Repository Notice & Operational Boundaries:**
> - **Public Lab Environment:** This public repository (`lopes/graft`) is strictly connected to an isolated lab/demo environment for open-source development and experimentation. It is never connected to production tenants.
> - **Production Repositories Must Be Private:** Any detection engineering team or operator adopting or forking Graft for production use **must maintain their repository in private version control** under strict organizational access controls. While the Graft engine is open-source, version-controlling live production deployment states (`enabled`, `alerting`) or operational exclusions (e.g., `findingsRefinements` in Google SecOps) in a public repository will leak defensive postures, monitoring coverage blind spots, and internal entity identities (hostnames, IP ranges, usernames, service accounts).
> - **Curated Content Is Public:** The vendor-managed detection catalog metadata tracked in `rulesets/secops/managed/index.yaml` (category names, ruleset titles, descriptions, and catalog UUIDs) represents standard vendor content that is **publicly published** in official Google Cloud documentation. See [Google SecOps Curated Detections](https://docs.cloud.google.com/chronicle/docs/detection/curated-detections) and [Review Curated Detection Categories](https://docs.cloud.google.com/chronicle/docs/detection/cloud-threats-category).
> - **Specification & Architecture:** Complete architectural foundations, component specifications, and engineering directives are documented in [docs/README.md](docs/README.md) and [AGENTS.md](AGENTS.md).

---

## The Philosophy

In horticulture, **grafting** joins a shoot from one plant onto the rootstock of another, enabling distinct varieties to thrive as a single, resilient organism.

**Project Graft** brings this discipline to detection engineering. Security teams often find their threat detection logic fragmented across proprietary rule consoles, incompatible query syntaxes, and siloed pipelines.

Graft acts as the unified trunk:

- **Standardized Core:** Author, document, and test detection rules (`metadata`, `logic`, `deployment`, `runbook`, `tests`) alongside reusable, engine-agnostic contextual datasets (`datasets/<name>.yaml`) in a unified, version-controlled repository.
- **Resilient Branches (Ports & Adapters):** Seamlessly "graft" rules and datasets into production engines. Deploy natively into **Google SecOps** using YARA-L 2.0 and Data Tables today, and branch into auxiliary SIEMs, EDRs, or cloud telemetry tomorrow without refactoring engineering workflows.
- **Multi-Track Governance:** Manage reusable string datasets (`datasets/<name>.yaml`), bespoke organizational detections (`rulesets/<engine>/custom/`), and vendor-managed detections (`rulesets/<engine>/managed/index.yaml` and optional registered rule envelopes `rulesets/<engine>/managed/<rule_name>.yaml`) under GitOps plan/apply reconciliation.
- **Frictionless CI/CD:** Decouple detection authoring from manual UI workflows with automated schema validation, dataset cross-reference checks, pre-merge API syntax dry runs (e.g., `verifyRuleText` in Google SecOps), and synthetic replay testing against dedicated staging infrastructure.

---

## Architecture at a Glance

Graft follows strict **Hexagonal Architecture (Ports & Adapters)** structured into four decoupled layers:

<p align="center">
  <img src="assets/architecture-overview.svg" alt="Graft Architecture: CLI, GitOps, Core Hexagonal, and Pluggable Engines" width="780">
</p>

---

## Key Features

### 1. Modular Engine Architecture & Pluggable Adapters
Graft strictly decouples detection engineering logic from downstream SIEM and telemetry platforms using **Hexagonal Architecture (Ports & Adapters)**:
- **Self-Contained Engine Packages:** Every detection engine lives in an isolated directory under `src/graft/engines/<engine>/` housing its concrete API client, deployment adapter, engine-specific Draft 2020-12 schemas, and documentation.
- **Strict Protocol Boundaries:** Engines implement explicit standard library `typing.Protocol` ports (`DatasetPort`, `RuleDeployerPort`, `ManagedEnginePort`, `RuleCompilerPort`, `ReplayHarnessPort`). Core never adapts to an engine; engines adapt to Core.
- **Zero Core Cloud Dependencies:** The core substrate imports zero third-party SIEM SDKs or cloud libraries. It relies strictly on Python standard library modules (`urllib.request`, `dataclasses`, `argparse`, `subprocess`), guaranteeing fast, lightweight, and auditable execution.
- **Engine Scaffolding in Seconds:** Adding a new SIEM target (e.g. Microsoft Sentinel, Splunk ES, Elastic) requires no core refactoring. Running `graft new engine <name>` generates the complete directory structure, schema definitions, unit test scaffolds, and documentation templates instantly.

### 2. Actionable Detection Envelopes & Factual Lifecycle
Detection logic is only as effective as the context and operational response it enables:
- **Normalized 5-Block Rule Envelope:** Detections are authored in a standardized YAML envelope separating `metadata`, `logic`, `deployment`, `runbook`, and `tests`.
- **Embedded Operational Runbooks:** Every rule embeds mandatory, actionable triage playbooks directly alongside the detection logic (`context`, `triage`, and `response`), eliminating tribal knowledge and context switching for SOC analysts during live incident response.
- **Factual Lifecycle vs. "Maturity Score" Theater:** Graft rejects arbitrary 0–100 maturity guesses and manual status tags that rapidly become stale. Instead, Graft empirically computes factual lifecycle indicators directly from Git version history (first committer `author`, UTC `YYYY-MM-DD` `created_at` and `last_modified_at`, `review_count`, and unique `contributor_count`) combined with accountable rule ownership (`owners`, `owner_count`) and active SIEM deployment health.

### 3. Reusable Datasets & Self-Expiring Suppressions (`ttl:YYYY-MM-DD`)
Contextual allowlists and temporary suppressions are notoriously hard to keep clean—a two-week penetration test IP added to a lookup table often stays there for a year because everyone forgets to remove it after the engagement ends:
- **Engine-Agnostic Datasets (`datasets/<name>.yaml`):** Track scanner IPs, assessment ranges, and privileged principals in a 2-block string-only YAML envelope (`metadata`, `values` of `0..1,000` literal strings) synchronized to SIEM lookup tables (e.g., Google SecOps Data Tables with a canonical `.value` column) via additive coexistence.
- **Inline Auto-Expiration (`ttl:YYYY-MM-DD`):** Append `ttl:YYYY-MM-DD` inside any value's inline `#` comment. The entry stays active through `YYYY-MM-DD` (UTC); starting the next UTC day, Graft omits it and the daily scheduled deployment removes it from the SIEM automatically—while preserving the line in Git as an audit trail.
- **Safe Deprecation (`datasets/_archived/`):** Moving a retired dataset to `datasets/_archived/` never breaks active rules referencing `%<name>.value`. Instead, Graft zeroes its rows on the SIEM and sets its remote description to `"Deprecated on Graft"` until you remove the rule references and delete the table remotely.

```yaml
# datasets/security_assessment_ips.yaml
values:
  - "192.0.2.10"  # External red team assessment jumpbox (TEST-NET-1) ttl:2026-12-31
  - "198.51.100.25"  # Authorized third-party pentest egress node (TEST-NET-2)
```

### 4. Multi-Track GitOps Drift Reconciliation
Modern SIEMs run a combination of contextual lookup tables, bespoke custom rules, and vendor-managed curated detections. Graft manages all three in strict dependency order (**1. Datasets $\rightarrow$ 2. Custom Rules $\rightarrow$ 3. Managed Content**) under unified version control:
- **Additive Dataset Synchronization:** Graft synchronizes `datasets/<name>.yaml` before rules are deployed, recreating active datasets if accidentally deleted in the SIEM console while never flagging or deleting unmanaged external SIEM tables.
- **Custom Rule Synchronization:** Authors maintain declarative custom rules in Git (`rulesets/<engine>/custom/`). Graft calculates precise diffs between local state and live tenant APIs, automating safe creates and updates.
- **Vendor-Managed Curated Content Control & Registration:** Manage vendor curated rule sets (`rulesets/<engine>/managed/index.yaml`) directly in code. Operators can declare deployment tiers (e.g., `PRECISE` vs `BROAD` in Google SecOps), toggle alerting states, commit declarative rule exclusions (e.g., `findingsRefinements`), and optionally register managed rules (`rulesets/<engine>/managed/<rule_name>.yaml`) to map vendor coverage into MITRE ATT&CK matrices and catalogs.
- **Dual-Mode Drift Reconciliation:**
  - **Scoped PR Reconciliation (Default):** Evaluates only files modified in the active Git branch against tenant state, enabling lightning-fast pull request validations in CI/CD.
  - **Full Catalog Convergence (`--all`):** Scans the entire tenant catalog (on merge to `main` and daily at `00:00` UTC) to purge expired `ttl:YYYY-MM-DD` dataset entries and heal out-of-band console drift.
- **Day 0 Brownfield Ingestion:** Teams can adopt Graft on existing SIEM instances in minutes without disruption. Running `graft <engine> pull` reverse-synchronizes live tenant custom rules and curated content into clean Git-managed envelopes (and `graft <engine> pull --target datasets` imports compatible 1-column `STRING` tables on demand).

```bash
$ graft secops diff --env production
=== Datasets Diff ===
[+] Dataset to create: known_scanner_ips (3 rows)
[~] Dataset to update: security_assessment_ips (2 rows)

=== Custom Rules Diff ===
[+] Custom rule to create: multiple_hosts_scanned
[~] Custom rule to update: workspace_nrd_email_opened (ID: ru_12345678-abcd-ef01-2345-6789abcdef01)
[?] Untracked custom rule on tenant: legacy_unmanaged_alert (ID: ru_98765432-feee-dcba-0000-111122223333)

=== Google SecOps Managed Content Diff ===
[~] Deployment: ur_cloud_threats (PRECISE) | enabled: False -> True, alerting: False -> True
[+] Exclusion to create: excl_cloud_functions_pipeline_sa
[-] Exclusion to delete: excl_temp_maintenance_window
```

### 5. Threat Visibility, Audit-Ready Catalogs & ATT&CK v19.2 Layers
Bridge the gap between detection engineering code, SOC operations, and leadership reporting:
- **Multi-Format Detection Catalogs:** Export unified catalogs in interactive terminal tables, CSV spreadsheets, Markdown documentation (`docs/RULE_CATALOG.md`), or JSON for ingestion into security data lakes, BigQuery, Polars, or BI dashboards.
- **MITRE ATT&CK Enterprise v19.2 Matrix:** Built-in evaluation of tactics and sub-techniques (`TAxxxx:Tyyyy.zzz`) with automated cross-engine technique normalization and coverage analysis.
- **Official Navigator Layer Generation:** Generate color-graded MITRE ATT&CK Navigator v4.5/v5.2 layer files (`exports/secops_coverage.json`) with embedded rule metadata, deployment status, and direct source links for interactive heatmap visualization in the official ATT&CK Navigator.

```bash
$ graft export catalog
Rule Name                                 Engine  Type     Status   MITRE ATT&CK                        Owners     Reviews  Updated   
----------------------------------------  ------  -------  -------  ----------------------------------  ---------  -------  ----------
gcp_service_account_key_created           secops  custom   enabled  TA0003:T1098.001, TA0004:T1098.001  Joe Lopes  13       2026-10-01
gcp_storage_bucket_public_access_granted  secops  custom   enabled  TA0001:T1078.004, TA0112:T1685      Joe Lopes  11       2026-10-01
workspace_nrd_email_opened                secops  custom   enabled  TA0001:T1566.002                    Joe Lopes  9        2026-10-01
gcti_breach_network_indicator_matched     secops  managed  silent   TA0011:T1071.001                    Joe Lopes  2        2026-10-01
multiple_hosts_scanned                    secops  custom   enabled  TA0007:T1046                        Joe Lopes  1        2026-10-01
multiple_ports_scanned                    secops  custom   enabled  TA0007:T1046                        Joe Lopes  1        2026-10-01
```

<p align="center">
  <img src="assets/attack-navigator-layer.svg" alt="MITRE ATT&CK Navigator Coverage Heatmap" width="900">
</p>

---

## Choose Your Journey

Graft's documentation is organized around **three core engineering personas**:

| Persona | Focus & Deliverables | Primary Guide |
| :--- | :--- | :--- |
| 🎯 **Detection Engineer / Analyst** | Authors, modifies, lints, tests, and diffs detection rules on a daily basis. Previews pull requests and consults operational runbooks. | **[Analyst Guide](docs/analysts/README.md)**<br/>📖 **[Detection Recipes Cookbook](docs/analysts/recipes.md)** |
| 🛠️ **Platform & SecOps Engineer** | Bootstraps Graft into existing SIEM tenants, configures CI/CD pipelines, handles authentication (WIF/OIDC), and maintains production sync. | **[Operator Guide](docs/operators/README.md)**<br/>🔄 **[Day 0 Ingestion & Reverse Sync](docs/operators/adoption.md)** |
| 💻 **Core Developer** | Fixes bugs in core services, extends port protocols, builds new engine adapters, and enforces software architecture quality gates. | **[Developer Guide](docs/developers/README.md)**<br/>🔌 **[Pluggable Adapter Framework](docs/developers/framework.md)** |

For the complete architectural overview and philosophy, visit the **[Graft Documentation Hub (docs/README.md)](docs/README.md)**.

---

## Quick Start & CLI Reference

### Prerequisites
- **Python >= 3.13**
- **[uv](https://docs.astral.sh/uv/)** (Fast Python package and project manager)
- **Google Cloud SDK (`gcloud`)** with access to a Google SecOps tenant instance (see [docs/engines/secops.md](docs/engines/secops.md))

### Installation & Quality Verification

```bash
# Clone repository
git clone https://github.com/lopes/graft.git
cd graft

# Install virtualenv and dev dependencies
uv sync

# Run static quality gates & test suite
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests
uv run pytest

# Optional: Enable native pre-commit hook (runs fast offline gates on git commit)
git config core.hooksPath .githooks
```

### Brownfield Adoption: Fastest Path (Day 0 Ingestion)

When adopting Graft on an existing SIEM instance, follow the 3-step bootstrap workflow (see [docs/operators/adoption.md](docs/operators/adoption.md) for full architectural specification):

```bash
# 1. Reverse sync existing custom rules & curated content from live tenant
uv run graft secops pull --env production

# 2. Validate all imported envelopes against schemas & MITRE matrix
uv run graft lint

# 3. Commit baseline and declare Git as authoritative Source of Truth
git add rulesets/
git commit -m "secops: import production detection baseline"
git push origin main
```

### Essential CLI Commands

#### 1. Rule & Dataset Validation & Taxonomy Linting
```bash
# Lint all datasets and rules across the repository offline (<100ms)
graft lint

# Lint a specific rule or dataset file
graft lint rulesets/secops/custom/workspace_nrd_email_opened.yaml
graft lint datasets/known_scanner_ips.yaml

# Output structured JSON diagnostics for CI/CD pipelines
graft --json lint
```

#### 2. Rule, Dataset & Engine Scaffolding
```bash
# Bootstrap a new custom detection rule (creates 5-block envelope with schema defaults)
graft secops new powershell_payload_downloaded
# or using the engine-agnostic router:
graft new rule powershell_payload_downloaded --engine secops

# Bootstrap a new reusable string dataset (creates 2-block envelope in datasets/<name>.yaml)
graft new dataset known_scanner_ips

# Register an enabled vendor-managed rule from rulesets/<engine>/managed/index.yaml
graft secops new gcti_breach_network_indicator_matched --managed 433faf9e-4d51-f284-c35b-009528ecff05

# Bootstrap an entirely new detection engine adapter (code, schema, rules, tests)
graft new engine sentinel
```

Graft also includes repository-native AI agent skills under [`.agents/skills/`](.agents/skills/) for composable rule and dataset engineering (see [Rule Authoring Guide](docs/analysts/rule_authoring.md#ai-assisted-rule-authoring--review-agentsskills)):
- `/scaffold-dataset <context_or_path>`: Runs `graft new dataset` and populates `metadata` and `values` for a reusable string dataset.
- `/scaffold-rule <context_or_path>`: Runs `graft new rule` and populates `metadata` and `runbook` while leaving `logic`, `deployment`, and `tests` untouched.
- `/scaffold-tests <rule_path>`: Parses authored `logic` predicates to generate positive (`match_*`) and negative (`ignore_*`) synthetic event vectors in `tests`.
- `/review-rule [path_or_dir]`: Runs `graft lint` and performs a read-only 5-block engineering audit (including `%<dataset>.value` cross-checks).

#### 3. Pre-Merge Verification & Staging Replay Testing
```bash
# Dry-run YARA-L syntax against Google SecOps verifyRuleText (non-destructive)
graft secops verify rulesets/secops/custom/workspace_nrd_email_opened.yaml

# Execute synthetic UDM replay tests in isolated staging quarantine (pre-syncs referenced datasets)
graft secops test

# Test only rules modified in the current Git branch or working tree
graft secops test --changed-only

# Enforce hard failure if staging credentials are missing (used in strict CI)
graft secops test --require-staging
```

#### 4. GitOps Drift Detection & State Reconciliation
```bash
# Preview changes for datasets and rules modified in current branch (Scoped Reconciliation: default)
graft secops diff --env production

# Scan entire tenant catalog for out-of-band console drift (Full Catalog Reconciliation: --all)
graft secops diff --all --env production

# Apply scoped branch changes to tenant in order: Datasets -> Custom Rules -> Managed Content
graft secops apply --env production

# Force complete tenant convergence back to Git state, healing any console drift (Full Catalog Reconciliation)
graft secops apply --all --env production

# Target only datasets, custom rules, or vendor-managed curated content
graft secops diff --target datasets --env production
graft secops diff --target custom --env production
graft secops apply --target managed --env production
```

#### 5. Reverse Synchronization (Tenant Ingestion)
```bash
# Reverse-sync live tenant custom rules and managed curated manifest into local repo
graft secops pull --env production

# Reverse-sync only custom rules (with overwrite protection or --force)
graft secops pull --target custom --env production --force

# Opt-in reverse-sync for compatible 1-column STRING Data Tables (originalColumn == "value")
graft secops pull --target datasets --env production

# Granular reverse-sync for vendor-curated rule sets only
graft secops managed pull --env production
```

#### 6. Threat Matrix & Visibility Catalogs
```bash
# Render on-screen detection catalog table (default format)
graft export catalog

# Filter catalog or matrix by target engine
graft export catalog --engine secops
graft export matrix --format table --engine secops

# Generate official MITRE ATT&CK Enterprise v19.2 Navigator layer (custom color gradient)
graft export matrix --format navigator --engine secops --color "#4285F4" --out exports/secops_coverage.json

# Export detection catalog for audits and documentation pipelines
graft export catalog --format csv --out exports/detection_catalog.csv
graft export catalog --format markdown --out docs/RULE_CATALOG.md
graft export catalog --format json
```

> [!NOTE]
> **Factual Lifecycle Indicators vs. Static "Maturity" Fields:**
> Graft intentionally omits static `metadata.status` or `maturity` fields from rules. In real-world detection engineering, static maturity labels rapidly become stale, creating administrative toil and a false sense of security ("security theater"). Similarly, Graft avoids arbitrary 0–100 synthetic maturity scores.
>
> Instead, `graft export catalog` computes verified, objective indicators directly from version control, the rule envelope, and engine deployment adapters:
> - **VCS Lifecycle & Provenance:** First committer (`author`), first committed date (`created_at`), and latest revision date (`last_modified_at`) normalized to UTC `YYYY-MM-DD`.
> - **Peer Review Scrutiny:** Total git commit count across renames (`review_count`) and unique contributor count (`contributor_count`).
> - **Operational Ownership & Context:** Accountable rule owners (`owners`) and bus-factor indicator (`owner_count`), unified ATT&CK mappings (`mitre_attack: TAxxxx:Tyyyy.zzz`), and engine-evaluated deployment health (`status: enabled | silent | disabled`).
>
> Operators can pipe these indicators into data pipelines (e.g. Polars, BigQuery, Google Sheets, BI dashboards) and combine them with live operational telemetry from the SIEM (alert volume, true-positive precision, mean time to triage) to assess true detection maturity objectively.

>
> **Rule & Dataset Decommissioning & Archiving:**
> When retiring a rule or dataset, move it to `rulesets/<engine>/_archived/` or `datasets/_archived/` rather than immediately deleting it. Rules in `_archived/` are excluded from loading, linting, matrix exports, and sync. Datasets in `datasets/_archived/` are skipped by `graft lint` and automatically emptied (`0` rows) and marked `"Deprecated on Graft"` on the SIEM during `diff`/`apply`, ensuring rules referencing `%<name>.value` never break before you remove the reference and delete the remote table.

---

## Platform Architecture & Governance

Comprehensive documentation tracks for Detection Engineers, SecOps Operators, and Core Developers are available in the **[Graft Documentation Hub (docs/README.md)](docs/README.md)**.

Operational directives, strict stdlib-first constraints, coding standards, and agent guidelines are documented in **[AGENTS.md](AGENTS.md)**.

---

## License & Disclaimer

### License
This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for full license terms.

### Disclaimer
> [!WARNING]
> Graft is personal research and not an officially supported Google product. All code and configurations are provided as-is without warranty or official SLA.

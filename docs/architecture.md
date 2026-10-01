# Graft Architecture & System Design

> **High-Level Architectural Reference & System Topology**  
> **Platform:** Extensible Detection-as-Code (DaC)  
> **Architecture:** Hexagonal Architecture (Ports & Adapters) | **Runtime:** Python >= 3.13 Stdlib-First

---

## 1. Architectural Philosophy: Hexagonal Boundaries

In Graft, detection business logic, domain models, schema validators, and governance tools remain 100% engine-agnostic. The core never adapts to an external SIEM or detection engine; engines adapt to Core via port contracts.

```mermaid
flowchart TD
    subgraph DrivingAdapters["Driving Adapters (CLI & Automation)"]
        CLI["graft CLI Dispatcher<br/><code>argparse</code>"]
        CI["CI/CD Gate Pipelines<br/>GitHub Actions"]
    end

    subgraph DrivingCore["Driving Core (src/graft/core/)"]
        PORTS["Engine Ports (typing.Protocol)<br/>• DatasetPort<br/>• RuleCompilerPort<br/>• RuleDeployerPort<br/>• ManagedEnginePort<br/>• ReplayHarnessPort"]
        MODELS["Domain Models (dataclasses)<br/>• DatasetEnvelope<br/>• RuleEnvelope<br/>• ManagedState<br/>• CompilationResult<br/>• ReconciliationDiff"]
        SERVICES["Core Services<br/>• SchemaValidator<br/>• MitreValidator<br/>• DatasetReconciler &amp; GitOpsReconciler<br/>• GitBlameExtractor<br/>• Matrix &amp; Catalog Exporters"]
        REGISTRY["EngineRegistry<br/>(Dynamic Manifest Discovery)"]
    end

    subgraph DrivenEngines["Driven Engines (src/graft/engines/)"]
        SECOPS["Google SecOps Engine<br/>• Chronicle REST Client (urllib)<br/>• Data Tables Dataset Adapter<br/>• YARA-L Compiler Adapter<br/>• Custom Rule Deployer<br/>• Curated RuleSet Reconciler<br/>• Staging Replay Harness"]
        FUTURE["Future Engines<br/>• Microsoft Sentinel<br/>• Splunk<br/>• CrowdStrike"]
    end

    DrivingAdapters --> REGISTRY
    REGISTRY --> PORTS
    PORTS --> MODELS
    SERVICES --> MODELS
    PORTS --> DrivenEngines
```

---

## 2. Abstraction Layers & Core Port Protocols

The platform divides into three decoupled layers:

1. **Driving Adapters (`src/graft/cli/`):** Command-line routing using Python standard library `argparse`. Dynamically provisions subcommands based on manifest capabilities.
2. **Driving Core (`src/graft/core/`):** Pure Python domain logic. Zero imports of cloud SDKs, SIEM client libraries, or HTTP frameworks. Declares abstract port contracts via `typing.Protocol`:
   - [`EngineAdapter`](../src/graft/core/ports/engine.py): Composite adapter interface.
   - [`DatasetPort`](../src/graft/core/ports/dataset.py): Reusable string dataset synchronization (additive coexistence).
   - [`RuleCompilerPort`](../src/graft/core/ports/compiler.py): Syntax validation and compilation diagnostics.
   - [`RuleDeployerPort`](../src/graft/core/ports/deployer.py): Rule CRUD and deployment state toggles.
   - [`ManagedEnginePort`](../src/graft/core/ports/managed.py): Vendor-managed content synchronization and exclusion management.
   - [`ReplayHarnessPort`](../src/graft/core/ports/replay.py): Synthetic event ingestion and quarantined rule evaluation.
3. **Driven Engines (`src/graft/engines/`):** Concrete engine adapters implementing port interfaces. Adapters carry the complete burden of translating external vendor APIs, authenticating, and mapping domain envelopes to engine-native formats.

For a comprehensive technical deep-dive into the framework, protocol signatures, and dynamic discovery, see:
👉 **[Pluggable Engine Adapter Framework](developers/framework.md)**

---

## 3. Multi-Track Content Governance & Ruleset/Dataset Taxonomy

Graft organizes detection content into three active tracks plus archival directories:

```mermaid
flowchart LR
    REPO["Graft Repository"] --> DATASETS["<b>Reusable Datasets</b><br/>datasets/&lt;name&gt;.yaml<br/>2-Block String Lists shared across engines"]
    REPO --> CUSTOM["<b>Custom Detections</b><br/>rulesets/&lt;engine&gt;/custom/*.yaml<br/>5-Block Envelope authored &amp; owned by organization"]
    REPO --> MANAGED["<b>Managed Detections</b><br/>rulesets/&lt;engine&gt;/managed/index.yaml (State Manifest)<br/>rulesets/&lt;engine&gt;/managed/&lt;rule&gt;.yaml (Optional Registration)"]
    REPO --> ARCHIVED["<b>Archived Content</b><br/>datasets/_archived/*.yaml<br/>rulesets/&lt;engine&gt;/_archived/*.yaml"]

    DATASETS --> VERIFY["CI: Lint + Cross-Check + Syntax Dry-Run + Replay Test"]
    CUSTOM --> VERIFY
    DATASETS --> RECONCILE["CI/CD: GitOps Plan (diff) &amp; Apply<br/>(1. Datasets → 2. Custom → 3. Managed)"]
    CUSTOM --> RECONCILE
    MANAGED --> RECONCILE
```

- **Track 1: Reusable Datasets (`datasets/<name>.yaml`):** Engine-agnostic 2-block string lists (`metadata`, `values`) validated against `base_dataset.schema.json`. Synchronized to engines supporting `datasets: true` (e.g., Google SecOps Data Tables with a single `STRING` column named `value`) via additive coexistence (unmanaged SIEM tables are never flagged as untracked or deleted).
- **Track 2: Custom Rules (`rulesets/<engine>/custom/*.yaml`):** Bespoke organizational detections packaged in the 5-block envelope (`metadata`, `logic`, `deployment`, `runbook`, `tests`).
- **Track 3: Vendor-Managed Content (`rulesets/<engine>/managed/`):**
  - `rulesets/<engine>/managed/index.yaml`: Single declarative manifest tracking deployment state (`enabled`, `alerting`, and engine-specific tiers such as `PRECISE` vs. `BROAD` in Google SecOps) and active exclusions for vendor-provided rulesets.
  - `rulesets/<engine>/managed/<rule_name>.yaml`: Optional 4-block registered managed rule envelopes (`metadata`, `managed`, `runbook`, `tests`) linking via `managed.id` to `index.yaml` so vendor coverage is mapped into MITRE ATT&CK matrices and catalogs.
- **Decommissioned Content (`datasets/_archived/` & `rulesets/<engine>/_archived/`):** Standard locations for retired datasets and detections. Any directory or file starting with an underscore (`_`) under `datasets/` or a ruleset (e.g. `_archived/`, `_deprecated/`, `_templates/`) is excluded from discovery, linting, matrix generation, and deployment synchronization.
- **Objective Visibility & Rigor (`graft export catalog`):** Rather than tracking subjective or stale `status` and `maturity` fields in rule files, Graft extracts factual VCS and envelope indicators (`author`, `owners`, `owner_count`, `created_at`, `last_modified_at`, `review_count`, `contributor_count`) and resolves live engine deployment state (`status: enabled | silent | disabled`). Operators combine these with live SIEM performance data to measure true detection quality.


---

## 4. GitOps Reconciliation Lifecycle

Git is declared the single authoritative Source of Truth for detection state, reconciled in strict dependency order (**1. Datasets $\rightarrow$ 2. Custom Rules $\rightarrow$ 3. Managed Content**):

- **Scoped Reconciliation (Default):** Restricts diffs and deployments strictly to datasets and rules modified in the current Git branch or working tree (`graft <engine> diff / apply`). Keeps pull requests focused and minimizes blast radius.
- **Full Catalog Reconciliation (`--all`):** Evaluates the entire repository catalog against the live tenant (`graft <engine> diff --all / apply --all`). Automatically discovers and heals out-of-band console drift.

For full operational reconciliation mechanics, see:
👉 **[GitOps Reconciliation & Detection Synchronization](operators/gitops_reconciliation.md)**

---

## 5. Persona Guides & Navigation

For tailored documentation, explore the dedicated tracks:
- **[Analyst Track (Detection Engineers)](analysts/README.md)** &mdash; Daily rule lifecycle and [Recipes Cookbook](analysts/recipes.md).
- **[Operator Track (Platform Engineers)](operators/README.md)** &mdash; [Adoption Lifecycle](operators/adoption.md), [CI/CD](operators/cicd_and_infrastructure.md), and [Security](operators/security.md).
- **[Developer Track (Core Engineers)](developers/README.md)** &mdash; [Framework](developers/framework.md), [Extending Engines](developers/extending_engines.md), and [Quality Standards](developers/quality_and_standards.md).

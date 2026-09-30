# Graft Documentation Hub

Graft is an extensible, vendor-agnostic Detection-as-Code (DaC) platform engineered around strict **Hexagonal Architecture (Ports & Adapters)** and a **Stdlib-First** runtime discipline.

This documentation hub is structured around **three distinct engineering personas**, ensuring you get immediate, high-signal information relevant to your responsibilities without wading through unrelated platform internals.

---

## The Three Personas

```mermaid
flowchart TD
    subgraph Personas["Graft Engineering Personas"]
        ANALYST["<b>Detection Engineer / Analyst</b><br/>Authors & tests detection rules daily"]
        OPERATOR["<b>Platform / SecOps Engineer</b><br/>Deploys platform, configures CI/CD & manages drift"]
        DEVELOPER["<b>Core Developer</b><br/>Maintains core & implements new engine adapters"]
    end

    subgraph DocsTracks["Dedicated Documentation Tracks"]
        TRACK_A["<b>Analyst Track</b> (docs/analysts/)<br/>• 5-Block Envelope Specification<br/>• Detection Recipes Cookbook<br/>• Synthetic Replay Testing<br/>• MITRE Coverage & Catalogs"]
        TRACK_O["<b>Operator Track</b> (docs/operators/)<br/>• Day 0 Adoption & Reverse Sync<br/>• Scoped vs. Full Reconciliation<br/>• CI/CD & Workload Identity (WIF)<br/>• Multi-Tenant Topology & IAM"]
        TRACK_D["<b>Developer Track</b> (docs/developers/)<br/>• Pluggable Adapter Framework<br/>• EngineAdapter Port Contracts<br/>• Scaffolding New Engines<br/>• Stdlib-First & TDD Gates"]
    end

    ANALYST --> TRACK_A
    OPERATOR --> TRACK_O
    DEVELOPER --> TRACK_D
```

---

## Choose Your Path

| Role | Responsibilities | Primary Documentation |
| :--- | :--- | :--- |
| **Detection Engineer / Analyst** | Authors, modifies, tests, and diffs detection rules on a daily basis. Previews pull requests and consults operational runbooks. | 🎯 **[Analyst Guide](analysts/README.md)**<br/>📖 **[Detection Recipes Cookbook](analysts/recipes.md)** |
| **Platform / SecOps Engineer** | Bootstraps Graft into existing SIEM tenants, configures CI/CD pipelines, handles authentication (WIF/OIDC), and maintains production sync. | 🛠️ **[Operator Guide](operators/README.md)**<br/>🔄 **[Day 0 Adoption & Ingestion](operators/adoption.md)** |
| **Core Developer** | Fixes bugs in core services, extends port protocols, builds new engine adapters, and enforces software architecture quality gates. | 💻 **[Developer Guide](developers/README.md)**<br/>🔌 **[Pluggable Adapter Framework](developers/framework.md)** |

---

## Architectural Foundations

Regardless of your persona, three foundational principles govern the platform:

### 1. Hexagonal Architecture (Ports & Adapters)
- **Driving Core (`src/graft/core/`):** 100% engine-agnostic domain logic. Implements rule parsing, schema validation, STIX MITRE matrices, Git blame extraction, and catalog export. **Zero imports of cloud SDKs or SIEM clients.**
- **Engine Ports (`src/graft/core/ports/`):** Strict `typing.Protocol` interfaces defining granular capabilities ([`RuleCompilerPort`](../src/graft/core/ports/compiler.py), [`RuleDeployerPort`](../src/graft/core/ports/deployer.py), [`ManagedEnginePort`](../src/graft/core/ports/managed.py), [`ReplayHarnessPort`](../src/graft/core/ports/replay.py)) and the composite [`EngineAdapter`](../src/graft/core/ports/engine.py).
- **Driven Engines (`src/graft/engines/`):** Self-contained, encapsulated packages (e.g., `secops`) carrying the full burden of translating external vendor APIs and query syntaxes. Core never adapts to an engine; engines adapt to Core.

### 2. Dual-Track Content Governance
Graft organizes detection content into two separate, version-controlled tracks:
- **Custom Rules (`rulesets/<engine>/custom/*.yaml`):** Bespoke organizational detections authored in a standardized 5-block envelope (`metadata`, `logic`, `deployment`, `runbook`, `tests`).
- **Managed Vendor Content (`rulesets/<engine>/managed/`):** Consolidated manifest (`managed/index.yaml`) managing deployment state (`PRECISE` vs. `BROAD`, `enabled`, `alerting`) and active exclusions for vendor-provided rulesets, paired with optional 4-block registered managed rule envelopes (`managed/<rule_name>.yaml`) for MITRE ATT&CK coverage and SOC runbooks.

### 3. GitOps Reconciliation Lifecycle
Git is declared the single authoritative Source of Truth for detection state:
- **Scoped Reconciliation (Default):** Restricts diffs and deployments strictly to rules touched in the current Git branch or working tree (`graft <engine> diff / apply`). Keeps PR reviews focused and minimizes blast radius.
- **Full Catalog Reconciliation (`--all`):** Evaluates the entire repository catalog against the live tenant (`graft <engine> diff --all / apply --all`). Automatically detects and heals out-of-band console drift.

---

## Foundational Literature & Core Theses

The architectural philosophy of Graft is directly grounded in foundational Detection-as-Code literature:

- **Joe Lopes — *Detection-as-Code, Then What?*:** Detection logic alone is not a rule; it is merely one component of a 5-block envelope (`metadata`, `logic`, `deployment`, `runbook`, `tests`). Schema validation must be decoupled from application code. Avoid data duplication by leveraging VCS for blame and timestamps. Co-locate incident response runbooks directly within detection artifacts. Value realization comes from operational visibility (factual catalogs) and ATT&CK coverage matrices, not raw rule counts.
- **NVISO Detection-as-Code Series (Parts 1–8):**
  - *Part 1 (Introduction & Lifecycle):* Standardizes the detection engineering lifecycle into iterative software sprints: requirements, development, verification, deployment, monitoring, and tuning.
  - *Part 2 (Repository Structure & Branching):* Establishes a monorepo topology with strict directory separation between core tooling, rule envelopes, schemas, and fixtures. Enforces trunk-based development with short-lived feature branches.
  - *Part 3 (Validation & Quality Gates):* Defines a multi-tier testing pyramid: static schema validation, offline syntax checking, STIX taxonomy verification, and automated dynamic replay testing.
  - *Part 4 (Documentation as Code):* Treats operational documentation as a build artifact, automatically deriving threat coverage, triage playbooks, and compliance catalogs from declarative envelopes.
  - *Part 5 (Versioning & Semantic Releases):* Applies Semantic Versioning (SemVer) to rulesets, tracking breaking changes in logic/contracts (Major), new detections (Minor), and tuning/runbook adjustments (Patch).
  - *Part 6 (CI/CD Deployment & State Management):* Formulates state synchronization using GitOps plan/apply principles, eliminating manual out-of-band console drift.
  - *Part 7 (Monitoring & Health Metrics):* Closes the telemetry feedback loop post-deployment, tracking rule execution health, error rates, and alert volumes.
  - *Part 8 (Tuning & Feedback Loops):* Manages rule exclusions and threshold adjustments declaratively in code with structured review histories.

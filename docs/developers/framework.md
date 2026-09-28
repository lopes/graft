# Pluggable Engine Adapter Framework

> **Architectural Specification, Abstraction Layers, and Protocol Contracts**  
> **Target Audience:** Engine Developers, Core Contributors, Platform Architects  
> **Guiding Paradigm:** Hexagonal Architecture (Ports & Adapters), Strict Protocol Subtyping, Stdlib-First

---

## 1. Architectural Philosophy & Abstraction Layers

Graft is engineered to decouple detection engineering logic, governance, and CI/CD pipelines from the peculiarities of specific SIEM or cloud analytics vendors. 

To achieve this, Graft implements **Hexagonal Architecture (Ports & Adapters)**. The Core domain sits at the center of the hexagon, isolated behind port protocols (`typing.Protocol`). External engines adapt to Core; Core never adapts to an engine.

```mermaid
flowchart TD
    subgraph DrivingAdapters["Driving Adapters (CLI & Workflows)"]
        CLI["graft CLI Dispatcher<br/>(argparse)"]
        ENGINE_CTRL["EngineCommandController<br/>(Dynamic CLI Routing)"]
        GHA["GitHub Actions CI/CD<br/>(pr-validation, deploy-production)"]
    end

    subgraph DrivingCore["Driving Core (src/graft/core/)"]
        direction TB
        REGISTRY["EngineRegistry<br/>(Dynamic Manifest & Schema Discovery)"]
        
        subgraph Ports["Port Protocols (typing.Protocol)"]
            P_ADAPTER["EngineAdapter (Composite)"]
            P_COMPILER["RuleCompilerPort"]
            P_DEPLOYER["RuleDeployerPort"]
            P_MANAGED["ManagedEnginePort"]
            P_REPLAY["ReplayHarnessPort"]
        end

        subgraph CoreServices["Core Services & Domain Models"]
            MODELS["Domain Models<br/>(RuleEnvelope, ManagedState, etc.)"]
            RECONCILER["GitOps & Custom Rule Reconcilers"]
            VALIDATORS["SchemaValidator & MitreValidator"]
            VCS["Git Blame & Change Detection"]
        end
    end

    subgraph DrivenAdapters["Driven Adapters (src/graft/engines/)"]
        direction TB
        SECOPS["Google SecOps Adapter<br/>• YARA-L Compiler<br/>• Chronicle REST Deployer<br/>• Curated RuleSet Reconciler<br/>• UDM Staging Replay"]
        SENTINEL["Microsoft Sentinel Adapter<br/>• KQL Compiler<br/>• Azure ARM/REST Deployer<br/>• Analytics Templates"]
        SPLUNK["Splunk Adapter<br/>• SPL Compiler<br/>• Saved Searches REST API"]
    end

    DrivingAdapters --> REGISTRY
    REGISTRY --> ENGINE_CTRL
    ENGINE_CTRL --> P_ADAPTER
    P_ADAPTER --> P_COMPILER
    P_ADAPTER --> P_DEPLOYER
    P_ADAPTER --> P_MANAGED
    P_ADAPTER --> P_REPLAY
    Ports --> CoreServices
    Ports -.-> DrivenAdapters
```

### The Three Abstraction Layers

1. **Driving Adapters (`src/graft/cli/`):**
   - Implemented using standard library `argparse`.
   - The CLI dispatcher initializes [`EngineRegistry`](../../src/graft/core/engine_registry.py), inspects all discovered engine manifests, and registers CLI subcommands dynamically.
   - Dispatches user requests to [`EngineCommandController`](../../src/graft/cli/engine_controller.py).
2. **Driving Core (`src/graft/core/`):**
   - 100% engine-agnostic domain models (`RuleEnvelope`, `ManagedState`, `TestVector`, `CompilationResult`, `ReconciliationDiff`).
   - Declares the abstract port contracts using Python's `typing.Protocol` with `@runtime_checkable`.
   - Provides reusable business logic: Draft 2020-12 schema validation, STIX MITRE ATT&CK taxonomy validation, Git diff/blame resolution, zero-cost state reconciliation, and report generation (ATT&CK Navigator layers, Markdown/CSV catalogs).
   - **Strict Constraint:** Core contains **zero imports** of cloud SDKs, SIEM client libraries, or HTTP clients.
3. **Driven Adapters (`src/graft/engines/<engine>/`):**
   - Concrete implementations of the port protocols.
   - Encapsulates all vendor-specific REST API calls, OAuth2 / Workload Identity Federation authentication, query compilation/deconstruction, and synthetic replay execution.
   - Lives in isolated, self-contained packages under `src/graft/engines/`.

---

## 2. Core Expectations vs. Adapter Responsibilities

To maintain strict architectural boundaries, responsibilities are cleanly divided between Core and Adapters:

| Capability / Concern | Handled by Driving Core | Handled by Driven Adapter |
| :--- | :--- | :--- |
| **Rule Representation** | Provides universal 5-block `RuleEnvelope` model and base JSON schemas. | Maps envelope fields (`metadata`, `logic`, `deployment`) to engine-native payload formats. |
| **Detection Rule Schema** | Loads and validates base envelope structure (`metadata`, `runbook`, `tests`). | Provides `schemas/rule.schema.json` (extending `base_rule.schema.json`) to validate engine-specific deployment and logic constraints. |
| **Reconciliation Logic** | Computes diffs, evaluates Scoped vs. Full Catalog scopes, and determines required mutations. | Executes atomic remote API calls (`create_rule`, `update_rule`, `set_rule_state`, `set_ruleset_deployment`). |
| **Authentication & HTTP** | Manages environment variable resolution and `.env` loading. | Establishes authenticated sessions (STS/WIF, OAuth2, API tokens) and issues HTTP requests via `urllib.request`. |
| **Syntax Verification** | Orchestrates file discovery and aggregates compiler results. | Invokes the vendor's syntax validation API (e.g., Chronicle `:verifyRuleText` or Azure API syntax check). |
| **Synthetic Replay** | Parses `tests:` block fixtures and evaluates expected match counts. | Transports synthetic events to staging infrastructure or non-alerting quarantine and executes detection evaluation. |
| **Vendor Managed Content** | Validates `managed.yaml` schema and computes exclusion/ruleset diffs. | Interacts with vendor curated rules APIs (e.g., Chronicle CuratedRuleSets or Sentinel Analytics Templates). |

---

## 3. Protocol Contracts & Method Signatures

Graft uses Python's `typing.Protocol` with structural subtyping (duck typing). Adapters do not need to inherit from concrete base classes; they simply implement the methods defined in `src/graft/core/ports/`.

### 1. Composite Adapter Protocol: `EngineAdapter`
Defined in [`src/graft/core/ports/engine.py`](../../src/graft/core/ports/engine.py):

```python
from typing import Protocol, runtime_checkable

from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort


@runtime_checkable
class EngineAdapter(Protocol):
    def __init__(self, env: str = "production") -> None: ...

    def get_compiler(self) -> RuleCompilerPort | None: ...

    def get_deployer(self) -> RuleDeployerPort | None: ...

    def get_managed(self) -> ManagedEnginePort | None: ...

    def get_replay(self) -> ReplayHarnessPort | None: ...

    def resolve_deployment_status(self, rule: RuleEnvelope) -> str: ...
```

The composite adapter acts as a capabilities factory and status resolver. Depending on which capabilities the engine supports, it returns the appropriate port implementation or `None`, and translates engine-specific deployment toggles into an engine-agnostic status (`enabled`, `silent`, `disabled`).

---

### 2. Rule Compiler Port: `RuleCompilerPort`
Defined in [`src/graft/core/ports/compiler.py`](../../src/graft/core/ports/compiler.py):

```python
from typing import Protocol
from graft.core.models.compiler import CompilationResult
from graft.core.models.rule import RuleEnvelope


class RuleCompilerPort(Protocol):
    def verify_syntax(self, rule_text: str) -> CompilationResult:
        """Verifies rule syntax with the remote engine API without deploying it."""
        ...

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        """Verifies full rule envelope syntax against the engine API."""
        ...
```

The returned [`CompilationResult`](../../src/graft/core/models/compiler.py) is an engine-agnostic dataclass:
```python
@dataclass(frozen=True)
class CompilationResult:
    success: bool
    diagnostics: tuple[CompilationDiagnostic, ...] = ()
    raw_Error: str | None = None
```

---

### 3. Rule Deployer Port: `RuleDeployerPort`
Defined in [`src/graft/core/ports/deployer.py`](../../src/graft/core/ports/deployer.py):

```python
from typing import Protocol
from graft.core.models.rule import RuleEnvelope


class RuleDeployerPort(Protocol):
    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        """Fetches all custom detection rules from the live tenant."""
        ...

    def create_rule(self, rule: RuleEnvelope) -> str:
        """Creates a new detection rule on the tenant and returns its remote ID."""
        ...

    def update_rule(self, rule: RuleEnvelope) -> None:
        """Updates an existing rule's logic and configuration in-place."""
        ...

    def delete_rule(self, rule_id: str) -> None:
        """Retires or deletes a rule on the remote tenant."""
        ...

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        """Updates deployment toggles without altering detection logic."""
        ...
```

---

### 4. Managed Content Port: `ManagedEnginePort`
Defined in [`src/graft/core/ports/managed.py`](../../src/graft/core/ports/managed.py):

```python
from typing import Protocol
from graft.core.models.managed import ManagedExclusion, ManagedState


class ManagedEnginePort(Protocol):
    def fetch_managed_state(self) -> ManagedState:
        """Fetches active vendor-curated ruleset deployments and exclusions."""
        ...

    def apply_managed_state(self, target_state: ManagedState) -> None:
        """Applies desired curated ruleset deployments and customer exclusions."""
        ...

    def set_ruleset_deployment(
        self,
        ruleset_id: str,
        deployment_type: str,
        enabled: bool,
        alerting: bool,
        category: str | None = None,
    ) -> None:
        """Updates a vendor ruleset deployment (e.g. PRECISE vs BROAD, enabled, alerting)."""
        ...

    def create_exclusion(self, exclusion: ManagedExclusion) -> str:
        """Creates a tuning filter/exclusion and returns its remote ID."""
        ...

    def update_exclusion(self, exclusion: ManagedExclusion) -> None:
        """Updates an existing tuning exclusion."""
        ...

    def delete_exclusion(self, exclusion_id: str) -> None:
        """Deletes a tuning exclusion from the tenant."""
        ...
```

---

### 5. Replay Harness Port: `ReplayHarnessPort`
Defined in [`src/graft/core/ports/replay.py`](../../src/graft/core/ports/replay.py):

```python
from typing import Protocol
from graft.core.models.rule import RuleEnvelope, TestVector


class ReplayHarnessPort(Protocol):
    def run_test_vector(self, rule: RuleEnvelope, vector: TestVector) -> ReplayResult:
        """Injects synthetic test events and verifies match count."""
        ...

    def is_available(self) -> bool:
        """Checks if the replay infrastructure or staging tenant is accessible."""
        ...
```

---

## 4. Custom Rules vs. Managed Rules: Definition & Strict Optionality

In modern SIEM architectures, detection content falls into two fundamentally distinct categories:

### 1. Definitions

| Concept | Custom Detection Rules | Vendor-Managed Content |
| :--- | :--- | :--- |
| **Ownership** | Authored and maintained 100% by the organization's detection engineers. | Authored and maintained by the SIEM vendor (e.g., Google Cloud Threat Intelligence, Microsoft Threat Experts). |
| **Representation** | Individual 5-block envelope YAML files under `rulesets/<engine>/custom/<rule>.yaml`. | Single consolidated manifest under `rulesets/<engine>/managed.yaml`. |
| **Logic Visibility** | Full query logic (`events`, `match`, `condition`) is authored and visible. | Proprietary vendor logic is black-boxed; operators configure operational parameters. |
| **Operator Control** | Complete CRUD control over queries, test vectors, and runbooks. | Toggles precision (`PRECISE` vs `BROAD`), activation, alert generation, and customer exclusion filters. |
| **Engine Port** | Handled via [`RuleDeployerPort`](../../src/graft/core/ports/deployer.py). | Handled via [`ManagedEnginePort`](../../src/graft/core/ports/managed.py). |

### 2. Strict Optionality via `capabilities`

Graft recognizes that **not all engines support both types of content**:
- A traditional log SIEM (e.g., Elasticsearch or Splunk) may only have custom detection queries and no vendor-managed curated rule subscription.
- A managed detection service or posture manager might only expose curated rule packages and customer exclusions without arbitrary query execution.
- Some platforms support both (e.g., Google SecOps with YARA-L custom rules and Google Cloud Curated Rule Sets).

Graft enforces strict optionality. Engines declare their supported feature set in their `engine.yaml` manifest:

```yaml
capabilities:
  custom_rules: true          # Engine supports custom detection rule CRUD
  syntax_verification: true   # Engine supports pre-merge syntax dry-runs
  managed_rules: false        # Engine DOES NOT have vendor-curated content
  replay_testing: false       # Engine DOES NOT have synthetic replay APIs
```

---

## 5. Capabilities-Driven CLI Provisioning

When Graft boots up, [`EngineRegistry`](../../src/graft/core/engine_registry.py) reads each engine's `engine.yaml`. The CLI controller inspects the declared capabilities and dynamically registers only the subcommands and arguments that the adapter actually supports:

```mermaid
flowchart TD
    MANIFEST["Engine Manifest (engine.yaml)"]
    CAPS["Evaluate capabilities:"]

    MANIFEST --> CAPS

    subgraph CustomBranch["custom_rules: true"]
        C_NEW["Provision 'graft &lt;engine&gt; new'"]
        C_DIFF["Provision 'graft &lt;engine&gt; diff'"]
        C_APPLY["Provision 'graft &lt;engine&gt; apply'"]
        C_PULL["Provision 'graft &lt;engine&gt; pull'"]
    end

    subgraph SyntaxBranch["syntax_verification: true"]
        S_VERIFY["Provision 'graft &lt;engine&gt; verify'"]
    end

    subgraph ReplayBranch["replay_testing: true"]
        R_TEST["Provision 'graft &lt;engine&gt; test'"]
    end

    subgraph ManagedBranch["managed_rules: true"]
        M_CMD["Provision 'graft &lt;engine&gt; managed'<br/>(diff, apply, pull)"]
        M_TARGET["Extend --target options:<br/>['custom', 'managed', 'all']"]
    end

    subgraph ManagedDisabled["managed_rules: false"]
        M_RESTRICT["Restrict --target options strictly to:<br/>['custom']"]
    end

    CAPS -- "custom_rules = true" --> CustomBranch
    CAPS -- "syntax_verification = true" --> SyntaxBranch
    CAPS -- "replay_testing = true" --> ReplayBranch
    CAPS -- "managed_rules = true" --> ManagedBranch
    CAPS -- "managed_rules = false" --> ManagedDisabled
```

### CLI Dynamic Adaptation Rules:
1. If `custom_rules: true`: Core registers `new`, `diff`, `apply`, and `pull`.
2. If `managed_rules: true`: Core registers the `managed` subcommand (`managed diff`, `managed apply`, `managed pull`) and enables `--target all|custom|managed` on `diff`, `apply`, and `pull`.
3. If `managed_rules: false`: The `managed` subcommand is completely omitted from the CLI help text, and `--target` on `diff/apply/pull` is locked strictly to `["custom"]`.
4. If `syntax_verification: true`: Core registers the `verify` command.
5. If `replay_testing: true`: Core registers the `test` command.

---

## 6. Dynamic Engine & Schema Discovery

Graft dynamically discovers engines without requiring hardcoded imports in Core:

1. **Manifest Discovery:** At startup, `EngineRegistry._discover()` scans all subdirectories under `src/graft/engines/` for `engine.yaml`.
2. **Manifest Validation:** Every manifest is validated against [`src/graft/core/schemas/engine_manifest.schema.json`](../../src/graft/core/schemas/engine_manifest.schema.json).
3. **Rule Schema Discovery:** When `graft lint` validates a rule or manifest for an engine, [`SchemaValidator`](../../src/graft/core/validation/schema_validator.py) checks for co-located schemas at:
   ```text
   src/graft/engines/<engine>/schemas/rule.schema.json
   src/graft/engines/<engine>/schemas/managed.schema.json
   ```
   If present, Core validates the rule envelope and managed manifest against these schemas without leaking vendor specifics into Core.
4. **Adapter Instantiation:** When an engine command is executed, Core dynamically imports the `adapter_class` declared in the manifest (e.g., `graft.engines.sentinel.adapter:SentinelAdapter`), instantiates it with the target environment (`env="production"`), and verifies that it implements [`EngineAdapter`](../../src/graft/core/ports/engine.py).

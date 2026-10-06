# Graft Detection Engines

In Graft, **Engines** are driven adapters that connect the platform-agnostic detection core to concrete SIEMs, EDR platforms, and cloud telemetry services.

---

## 1. Engine Directory Taxonomy

Every engine in Graft is packaged as a self-contained, encapsulated module under `src/graft/engines/<engine>/`:

```text
graft/
├── datasets/
│   ├── _archived/            # Decommissioned datasets preserved for audit history
│   └── <name>.yaml           # 2-block reusable string datasets shared across engines
├── src/graft/engines/<engine>/
│   ├── engine.yaml           # Declarative manifest (capabilities, envs, vars)
│   ├── .env.example          # Engine-scoped environment variable template
│   ├── adapter.py            # Primary EngineAdapter protocol implementation
│   ├── config.py             # Tenant coordinates & auth resolution
│   ├── datasets.py           # Dataset synchronization (DatasetPort)
│   ├── compiler.py           # Syntax verification (RuleCompilerPort)
│   ├── deployer.py           # Remote rule CRUD (RuleDeployerPort)
│   ├── managed.py            # Managed state sync (ManagedEnginePort)
│   ├── replay.py             # Synthetic replay harness (ReplayHarnessPort)
│   ├── schemas/              # Co-located engine schemas (custom.schema.json, managed.schema.json)
│   ├── docs/                 # Co-located engine setup guides & operational runbooks
│   └── README.md             # Engine package overview
├── tests/engines/<engine>/   # Engine unit & contract tests
└── rulesets/<engine>/
    ├── _archived/            # Decommissioned rules preserved for audit history
    ├── custom/               # 5-block envelope custom rules (.yaml)
    └── managed/
        ├── index.yaml        # Declarative vendor-managed content manifest
        └── <rule_name>.yaml  # Optional 4-block registered managed rule envelopes
```

---

## 2. Pluggable Discovery & Capabilities-Driven CLI Routing

Engines are discovered dynamically at runtime by [`EngineRegistry`](../../src/graft/core/engine_registry.py), which parses and validates each engine's `engine.yaml` against [`src/graft/core/schemas/engine_manifest.schema.json`](../../src/graft/core/schemas/engine_manifest.schema.json).

Based on the capabilities declared in `engine.yaml`, [`EngineCommandController`](../../src/graft/cli/engine_controller.py) automatically provisions subcommands:

```bash
graft <engine> [subcommands...]
```

For example, an engine declaring all five capabilities (such as `secops`) mounts:
- `graft <engine> new <name>`: Bootstrap a new custom rule envelope (or `--managed <id>` for a registered managed rule).
- `graft <engine> verify [paths...]`: Lint locally and dry-run query syntax via the engine's compiler API.
- `graft <engine> test [paths...]`: Execute synthetic replay tests in isolated staging quarantine (pre-syncing referenced local datasets).
- `graft <engine> diff`: Compute delta between Git and target tenant (supports `--target datasets|custom|managed|all` and `--all` for full catalog drift).
- `graft <engine> apply`: Apply desired Git state to target tenant in order (`datasets` $\rightarrow$ `custom` $\rightarrow$ `managed`).
- `graft <engine> pull`: Pull detection rules, managed state, or compatible datasets (`--target datasets`) from target tenant to local repository.
- `graft <engine> datasets {diff,apply,pull}`: Granular commands for reusable string datasets (`datasets/<name>.yaml`).
- `graft <engine> managed {diff,apply,pull}`: Granular commands for vendor-managed content and exclusions.

---

## 3. Available Documentation

Engine-specific setup guides, IAM policies, and operational runbooks are co-located directly inside each engine package under `src/graft/engines/<engine>/docs/`:

- **[Google SecOps (`secops`) Engine Package](../../src/graft/engines/secops/README.md) & [Setup & Operations Guide](../../src/graft/engines/secops/docs/README.md):** GCP IAM permissions, Workload Identity Federation provisioning, dual-tenant staging vs. production topologies, Data Tables synchronization, Curated Rule Sets, and `findingsRefinements` exclusion runbooks.
- **[Pluggable Engine Adapter Framework](../developers/framework.md):** Architectural specification, abstraction layers, Core ports, and dynamic capabilities-driven routing.
- **[Extending & Bootstrapping Engines](../developers/extending_engines.md):** Step-by-step developer tutorial on bootstrapping a new engine adapter (e.g. CrowdStrike, Microsoft Sentinel, Splunk) via `graft new engine`.

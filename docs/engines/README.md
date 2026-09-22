# Graft Detection Engines

In Graft, **Engines** are driven adapters that connect the platform-agnostic detection core to concrete SIEMs, EDR platforms, and cloud telemetry services.

---

## 1. Engine Directory Taxonomy

Every engine in Graft is packaged as a self-contained, encapsulated module under `src/graft/engines/<engine>/`:

```text
graft/
├── src/graft/engines/<engine>/
│   ├── engine.yaml           # Declarative manifest (capabilities, envs, vars)
│   ├── adapter.py            # Primary EngineAdapter protocol implementation
│   ├── config.py             # Tenant coordinates & auth resolution
│   ├── compiler.py           # Syntax verification (RuleCompilerPort)
│   ├── deployer.py           # Remote rule CRUD (RuleDeployerPort)
│   ├── managed.py            # Managed state sync (ManagedEnginePort)
│   ├── replay.py             # Synthetic replay harness (ReplayHarnessPort)
│   ├── schemas/              # Co-located engine schemas (rule.schema.json)
│   └── README.md             # Engine-specific documentation
├── tests/engines/<engine>/   # Engine unit & contract tests
└── rulesets/<engine>/
    ├── _archived/            # Decommissioned rules preserved for audit history
    ├── custom/               # 5-block envelope custom rules (.yaml)
    └── managed.yaml          # Declarative vendor-managed content manifest
```

---

## 2. Pluggable Discovery & Capabilities-Driven CLI Routing

Engines are discovered dynamically at runtime by [`EngineRegistry`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/core/engine_registry.py), which parses and validates each engine's `engine.yaml` against [`src/graft/core/schemas/engine_manifest.schema.json`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/core/schemas/engine_manifest.schema.json).

Based on the capabilities declared in `engine.yaml`, [`EngineCommandController`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/cli/engine_controller.py) automatically provisions subcommands:

```bash
graft <engine> [subcommands...]
```

For example, the Google SecOps engine mounts:
- `graft secops new <name>`: Bootstrap a new SecOps YARA-L rule envelope.
- `graft secops verify [paths...]`: Lint locally and dry-run YARA-L syntax via Chronicle `:verifyRuleText`.
- `graft secops test [paths...]`: Execute synthetic UDM replay tests in isolated staging quarantine.
- `graft secops diff`: Compute delta between Git and SecOps tenant (supports `--target custom|managed|all` and `--all` for full catalog drift).
- `graft secops apply`: Apply desired Git state to SecOps tenant (supports `--target custom|managed|all` and `--all` for full convergence).
- `graft secops pull`: Pull detection rules and managed state from SecOps tenant to local repository.
- `graft secops managed {diff,apply,pull}`: Granular commands for Google Curated Rule Sets and exclusions.

---

## 3. Available Documentation

- **[Google SecOps Engine Reference (`secops.md`)](secops.md):** Configuration, IAM permissions, dual-tenant staging vs prod topologies, single-tenant lab mode, and API mechanics.
- **[Pluggable Engine Adapter Framework](../developers/framework.md):** Architectural specification, abstraction layers, Core ports, and dynamic capabilities-driven routing.
- **[Extending & Bootstrapping Engines](../developers/extending_engines.md):** Step-by-step developer tutorial on bootstrapping a new engine adapter (e.g. CrowdStrike, Microsoft Sentinel, Splunk) via `graft new engine`.

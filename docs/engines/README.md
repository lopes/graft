# Graft Detection Engines

In Graft, **Engines** are driven adapters that connect the platform-agnostic detection core to concrete SIEMs, EDR platforms, and cloud telemetry services.

---

## 1. Engine Directory Taxonomy

Every engine in Graft has a consistent physical structure across source code, rules, and schemas:

```text
graft/
├── src/graft/engines/<engine>/    # Engine adapter implementation & REST clients
├── rules/<engine>/
│   ├── custom/                    # 5-block envelope custom rules (.yaml)
│   └── managed.yaml               # Declarative vendor-managed content manifest
└── schemas/<engine>_custom.schema.json  # Engine-specific schema extensions
```

---

## 2. Pluggable Discovery & CLI Routing

Engines are automatically discovered at runtime by inspecting subdirectories of `src/graft/engines/`. When an engine provides a `register_subcommand(subparsers)` hook in `src/graft/cli/engines/<engine>.py`, Graft dynamically mounts its top-level commands into the CLI router:

```bash
graft <engine> [subcommands...]
```

For example, the Google SecOps engine mounts:
- `graft secops verify`: Compiles YARA-L logic pre-merge via `:verifyRuleText`.
- `graft secops test`: Executes quarantined synthetic UDM replay tests.
- `graft secops managed diff`: Compares desired `managed.yaml` against live Curated Rule Sets.
- `graft secops managed apply`: Applies desired managed configuration to the tenant.
- `graft secops managed pull`: Serializes live tenant state to local YAML manifest.

---

## 3. Available Documentation

- **[Google SecOps Engine (`secops.md`)](secops.md):** Configuration, IAM permissions, dual-tenant staging vs prod topologies, single-tenant lab mode, and API mechanics.
- **[Extending & Bootstrapping Engines (`extending_engines.md`)](extending_engines.md):** Step-by-step developer tutorial on bootstrapping a new engine adapter (e.g. CrowdStrike, Microsoft Sentinel, Splunk) via `graft new engine`.

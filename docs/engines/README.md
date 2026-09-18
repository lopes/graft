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
- `graft secops new <name>`: Bootstrap a new SecOps YARA-L rule envelope.
- `graft secops verify [paths...]`: Lint locally and dry-run YARA-L syntax via Chronicle `:verifyRuleText`.
- `graft secops test [paths...]`: Execute synthetic UDM replay tests in isolated staging quarantine.
- `graft secops diff`: Compute delta between Git and SecOps tenant (supports `--target custom|managed|all` and `--all` for full catalog drift).
- `graft secops apply`: Apply desired Git state to SecOps tenant (supports `--target custom|managed|all` and `--all` for full convergence).
- `graft secops pull`: Pull detection rules and managed state from SecOps tenant to local repository.
- `graft secops managed {diff,apply,pull}`: Granular commands for Google Curated Rule Sets and exclusions.

---

## 3. Available Documentation

- **[Google SecOps Engine (`secops.md`)](secops.md):** Configuration, IAM permissions, dual-tenant staging vs prod topologies, single-tenant lab mode, and API mechanics.
- **[Extending & Bootstrapping Engines (`extending_engines.md`)](extending_engines.md):** Step-by-step developer tutorial on bootstrapping a new engine adapter (e.g. CrowdStrike, Microsoft Sentinel, Splunk) via `graft new engine`.

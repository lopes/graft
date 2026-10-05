# Google SecOps (`secops`) Engine Adapter

Driven engine adapter connecting Graft's hexagonal detection core to the **Google SecOps (Chronicle SIEM)** REST API (`v1` and `v1alpha`).

---

## Package Layout

- [`engine.yaml`](engine.yaml) — Engine manifest declaring capabilities (`custom_rules`, `syntax_verification`, `managed_rules`, `replay_testing`, `datasets`) and environment variables.
- [`.env.example`](.env.example) — Engine-scoped environment variable template (`GRAFT_SECOPS_*`).
- [`adapter.py`](adapter.py) — [`SecOpsAdapter`](adapter.py), the primary `EngineAdapter` composite implementation, default YARA-L rule logic provider, `%<dataset>.value` cross-reference validator, and three-tier semantic rule matcher (`secops_rule_content_matches`).
- [`config.py`](config.py) — [`SecOpsConfig`](config.py), resolving dual-tenant (`staging` / `production`) and single-tenant fallback coordinates.
- [`auth.py`](auth.py) — [`SecOpsAuthenticator`](auth.py), zero-dependency OAuth 2.0 / Workload Identity Federation / `gcloud` token resolution.
- [`client.py`](client.py) — [`SecOpsClient`](client.py), `urllib.request` REST client for Chronicle `v1` and `v1alpha` endpoints.
- [`datasets.py`](datasets.py) — [`SecOpsDatasetAdapter`](datasets.py), synchronizing reusable string datasets (`datasets/<name>.yaml`) to Google SecOps Data Tables (`dataTables`, single `STRING` column named `value`).
- [`compiler.py`](compiler.py) — [`SecOpsCompilerAdapter`](compiler.py), YARA-L 2.0 synthesis, deconstruction (`deconstruct_yaral_rule`), and `:verifyRuleText` dry-run validation (with local dataset placeholder substitution).
- [`deployer.py`](deployer.py) — [`SecOpsDeployerAdapter`](deployer.py), custom rule CRUD and in-place revision reconciliation.
- [`managed.py`](managed.py) & [`managed_loader.py`](managed_loader.py) — [`SecOpsManagedAdapter`](managed.py), managing Google Cloud Curated Rule Sets (`PRECISE` / `BROAD`) and `findingsRefinements` exclusions.
- [`replay.py`](replay.py) — [`SecOpsReplayEngine`](replay.py), quarantined synthetic UDM replay test harness (with automatic staging dataset pre-sync).
- [`schemas/`](schemas/) — Co-located JSON Schemas (`custom.schema.json` and `managed.schema.json`).
- [`docs/`](docs/) — Co-located Google SecOps engine setup, provisioning, and operational runbooks.

---

## Authoritative Documentation

For complete setup instructions, GCP IAM roles, Workload Identity Federation provisioning, Data Tables synchronization, Curated Rule Sets, `findingsRefinements` exclusion runbooks, reconciliation architecture, and Cloud Audit Log queries, see the co-located engine documentation:

- **[Google SecOps Engine Setup & Operations Guide (`docs/README.md`)](docs/README.md)**

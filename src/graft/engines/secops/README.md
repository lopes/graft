# Google SecOps (`secops`) Engine Adapter

Driven engine adapter connecting Graft's hexagonal detection core to the **Google SecOps (Chronicle SIEM)** REST API (`v1` and `v1alpha`).

---

## Package Layout

- [`engine.yaml`](engine.yaml) — Engine manifest declaring capabilities (`custom_rules`, `syntax_verification`, `managed_rules`, `replay_testing`) and environment variables.
- [`adapter.py`](adapter.py) — [`SecOpsAdapter`](adapter.py), the primary `EngineAdapter` composite implementation and three-tier semantic rule matcher (`secops_rule_content_matches`).
- [`config.py`](config.py) — [`SecOpsConfig`](config.py), resolving dual-tenant (`staging` / `production`) and single-tenant fallback coordinates.
- [`auth.py`](auth.py) — [`SecOpsAuthenticator`](auth.py), zero-dependency OAuth 2.0 / Workload Identity Federation / `gcloud` token resolution.
- [`client.py`](client.py) — [`SecOpsClient`](client.py), `urllib.request` REST client for Chronicle `v1` and `v1alpha` endpoints.
- [`compiler.py`](compiler.py) — [`SecOpsCompilerAdapter`](compiler.py), YARA-L 2.0 synthesis, deconstruction (`deconstruct_yaral_rule`), and `:verifyRuleText` dry-run validation.
- [`deployer.py`](deployer.py) — [`SecOpsDeployerAdapter`](deployer.py), custom rule CRUD and in-place revision reconciliation.
- [`managed.py`](managed.py) & [`managed_loader.py`](managed_loader.py) — [`SecOpsManagedAdapter`](managed.py), managing Google Cloud Curated Rule Sets (`PRECISE` / `BROAD`) and `findingsRefinements` exclusions.
- [`replay.py`](replay.py) — [`SecOpsReplayEngine`](replay.py), quarantined synthetic UDM replay test harness.
- [`schemas/`](schemas/) — Co-located JSON Schemas (`rule.schema.json` and `managed.schema.json`).

---

## Authoritative Documentation

For complete setup instructions, GCP IAM roles, Workload Identity Federation provisioning, Curated Rule Sets, `findingsRefinements` exclusion runbooks, and reconciliation architecture, see the canonical guide:

- **[Google SecOps Engine Reference (`docs/engines/secops.md`)](../../../../docs/engines/secops.md)**

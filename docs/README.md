# Graft Documentation

Welcome to the Graft documentation. This table of contents is arranged in a didactic reading order to guide you from core concepts to advanced engine development.

---

## Table of Contents

1. **[System Architecture](architecture.md)**  
   Core architectural principles, Hexagonal Ports & Adapters boundaries, driving vs driven layers, and standard library runtime constraints.

2. **[Rule Authoring Guide](rule_authoring.md)**  
   Comprehensive specification of the 5-block rule envelope (`metadata`, `logic`, `deployment`, `runbook`, `tests`), YARA-L logic patterns, and offline linting.

3. **[GitOps Reconciliation & Managed Content](gitops_reconciliation.md)**  
   Managing vendor-curated content (e.g. Google Curated Rule Sets) and exclusions in code, drift detection (`diff`), state reconciliation (`apply`), and reverse synchronization (`pull`).

4. **[Synthetic Replay Testing & Quarantine Harness](replay_testing.md)**  
   Dynamic validation using temporary non-alerting quarantined rules, synthetic UDM event ingestion, single-tenant lab mode, and graceful degradation in CI/CD.

5. **[Visibility, Threat Matrix & Rule Catalogs](visibility_and_matrix.md)**  
   Aggregating MITRE ATT&CK coverage, exporting ATT&CK Navigator v4 JSON layers, Git blame author attribution, and generating Markdown/CSV/JSON catalogs.

6. **[Detection Engines Overview](engines/README.md)**  
   Architecture of Graft's pluggable detection engine subsystem, engine directory taxonomy, and dynamic CLI discovery mechanisms.

7. **[Google SecOps Engine Setup & Credentials](engines/secops.md)**  
   GCP IAM service account setup, Workload Identity Federation (WIF), dual-tenant (Staging vs. Production) configuration, single-tenant lab topology, and Chronicle API endpoints.

8. **[Extending Engines Tutorial](engines/extending_engines.md)**  
   Step-by-step developer guide to scaffolding a new engine adapter via `graft new engine`, implementing the four core engine ports, and testing with strict TDD.

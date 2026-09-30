# Detection Engineer's Cookbook: Recipes to Manage Rules

This cookbook provides practical, copy-pasteable recipes for everyday detection engineering workflows in Graft. Google SecOps (Chronicle SIEM) is used as the primary reference implementation, but identical principles apply across all supported engines.

---

## Table of Recipes

1. [Recipe 1: Scaffolding a New Rule](#recipe-1-scaffolding-a-new-rule)
2. [Recipe 2: Authoring the 5-Block Envelope](#recipe-2-authoring-the-5-block-envelope)
3. [Recipe 3: Fast Offline Linting & Schema Validation](#recipe-3-fast-offline-linting--schema-validation)
4. [Recipe 4: Pre-Merge Remote Syntax Dry-Run](#recipe-4-pre-merge-remote-syntax-dry-run)
5. [Recipe 5: Writing and Running Synthetic Replay Tests](#recipe-5-writing-and-running-synthetic-replay-tests)
6. [Recipe 6: Previewing Scoped Changes Before Opening a PR](#recipe-6-previewing-scoped-changes-before-opening-a-pr)
7. [Recipe 7: Embedding Investigation Runbooks](#recipe-7-embedding-investigation-runbooks)
8. [Recipe 8: Safely Disabling or Deprecating a Rule](#recipe-8-safely-disabling-or-deprecating-a-rule)
9. [Recipe 9: Generating MITRE ATT&CK Matrices & Catalogs](#recipe-9-generating-mitre-attck-matrices--catalogs)
10. [Recipe 10: Registering & Mapping a Vendor-Managed Rule](#recipe-10-registering--mapping-a-vendor-managed-rule)

---

## Recipe 1: Scaffolding a New Rule

### Objective
Create a new detection rule file with an auto-generated UUID, valid schema defaults, and an initial test vector skeleton (or a 4-block registered managed rule envelope via `--managed <id>`).

### Command
```bash
# Custom rule — Using the engine-specific command:
graft secops new gcp_iam_service_account_key_create

# Custom rule — Or using the root command router:
graft new rule gcp_iam_service_account_key_create --engine secops

# Registered managed rule — Link to a vendor ID in rulesets/secops/managed/index.yaml:
graft secops new gcti_active_breach_network_indicators --managed 433faf9e-4d51-f284-c35b-009528ecff05
```

### Result
For custom rules, Graft creates `rulesets/secops/custom/gcp_iam_service_account_key_create.yaml` with pre-populated `metadata`, `logic`, `deployment`, `runbook`, and `tests` blocks. When `--managed <id>` is supplied, Graft creates `rulesets/secops/managed/<rule_name>.yaml` with `metadata`, `managed`, `runbook`, and `tests: []`.

---

## Recipe 2: Authoring the 5-Block Envelope

### Objective
Fill out the scaffolded rule with realistic detection logic, operational controls, and attack taxonomy.

### Rule Template
```yaml
metadata:
  id: "b1d72370-5fa3-4cb8-a579-22a468d6f101"
  name: "gcp_iam_service_account_key_create"
  description: "Long-lived user-managed GCP service account keys created."
  owners:
    - "Detection Engineering <detection@company.com>"
  mitre:
    persistence:
      - "T1098"
      - "T1098.001"
    privilege-escalation:
      - "T1078.004"
  tags:
    - "gcp"
    - "iam"
    - "service_account"
  references:
    - "https://cloud.google.com/iam/docs/creating-managing-service-account-keys"

logic: |
  events:
    $e.metadata.event_type = "USER_RESOURCE_CREATION"
    $e.metadata.product_name = "Google Cloud IAM"
    $e.security_result.action = "ALLOW"
    $e.target.resource.name = /google.iam.admin.v1.CreateServiceAccountKey/
  condition:
    $e

deployment:
  enabled: false
  alerting: false
  run_frequency: "live"

runbook:
  context: |
    Service account keys are long-lived credentials that authenticate as a service account.
    Adversaries often create user-managed keys to establish persistent API access to Google Cloud.
  triage: |
    1. Check $e.principal.user.userid to identify who created the key.
    2. Review recent audit logs for that principal to determine if this aligns with an approved Terraform or IAM ticket.
    3. Verify whether the key was created for an automated CI/CD pipeline or a human user.
  response: |
    1. If unauthorized, immediately delete the compromised service account key via `gcloud iam service-accounts keys delete`.
    2. Revoke active sessions for the principal account.
    3. Rotate any sensitive credentials accessible to the service account.

tests:
  - id: "positive_key_creation"
    description: "Matches when an IAM CreateServiceAccountKey event is recorded"
    expect: 1
    events:
      - timestamp: "2026-09-18T10:00:00Z"
        payload:
          metadata:
            event_type: "USER_RESOURCE_CREATION"
            product_name: "Google Cloud IAM"
          security_result:
            action: "ALLOW"
          target:
            resource:
              name: "google.iam.admin.v1.CreateServiceAccountKey"
```

---

## Recipe 3: Fast Offline Linting & Schema Validation

### Objective
Verify that rule YAML files conform to Draft 2020-12 JSON Schema, contain valid MITRE ATT&CK technique IDs, and have unique IDs across the repository.

### Commands
```bash
# Lint all rules in the repository (sub-second execution)
graft lint

# Lint only your modified rule file
graft lint rulesets/secops/custom/gcp_iam_service_account_key_create.yaml

# Output structured JSON for automation or pre-commit hooks
graft --json lint rulesets/secops/custom/gcp_iam_service_account_key_create.yaml
```

### Exit Codes
- `0`: All rules passed schema and taxonomy validation.
- `1`: Validation errors detected (schema failure, invalid MITRE technique ID, or duplicate UUID).

---

## Recipe 4: Pre-Merge Remote Syntax Dry-Run

### Objective
Verify that your YARA-L logic compiles cleanly against the real Google SecOps engine before submitting a pull request, without creating or modifying rules in production.

### Commands
```bash
# Dry-run syntax compilation against staging SecOps tenant
graft secops verify rulesets/secops/custom/gcp_iam_service_account_key_create.yaml

# Dry-run syntax across all custom rules in the engine
graft secops verify
```

### How It Works
Graft synthesizes the full YARA-L rule envelope in memory and invokes Chronicle's `:verifyRuleText` endpoint. If compilation errors occur, Graft translates Chronicle's line numbers back to the exact line in your YAML file.

---

## Recipe 5: Writing and Running Synthetic Replay Tests

### Objective
Test your detection logic against synthetic event fixtures in an isolated staging quarantine.

### Commands
```bash
# Run replay tests for a specific rule
graft secops test rulesets/secops/custom/gcp_iam_service_account_key_create.yaml

# Run tests only for rules modified in your current Git branch
graft secops test --changed-only

# Require staging credentials (fails if staging is unconfigured, used in CI)
graft secops test --require-staging
```

### How Quarantine Isolation Works
1. Graft uploads a temporary rule with a random UUID to staging (`graft_test_<name>_<hash>`) with alerting strictly disabled.
2. It injects the synthetic UDM event payloads defined in your `tests:` block.
3. It polls execution to assert that the match count equals your `expect:` value.
4. It **guarantees immediate cleanup and deletion** of the temporary quarantine rule, ensuring zero test alert pollution.

---

## Recipe 6: Previewing Scoped Changes Before Opening a PR

### Objective
Preview the exact plan delta (additions, modifications, deletions) that will be applied to the SIEM tenant when your branch merges.

### Command
```bash
# Preview scoped changes for your current working branch
graft secops diff --env production
```

### Scoped Reconciliation Guarantee
By default, `graft secops diff` operates in **Scoped Reconciliation Mode**. It evaluates *only* the detection files modified in `git diff origin/main...HEAD` + working tree. It completely ignores unrelated SIEM rules, providing a clean, noise-free review plan for your PR.

---

## Recipe 7: Embedding Investigation Runbooks

### Objective
Provide immediate operational context and triage instructions for SOC analysts directly inside the alert.

### Guidelines for Runbooks
- **Context:** State what attack technique this detects, adversary objectives, and common benign activity (false positives) in your environment.
- **Triage:** Numbered, sequential steps explaining which fields to inspect first (e.g. `principal.user.userid`, `target.resource.name`).
- **Response:** Concrete containment actions (e.g. credential revocation, network isolation, ticket templates).

---

## Recipe 8: Safely Disabling or Deprecating a Rule

### Scenario A: Temporarily Disabling Alerts (Tuning or Noise)
To silence alerts while keeping detection metrics active:
```yaml
deployment:
  enabled: true
  alerting: false    # Matches recorded, but zero SOC alerts generated
```

### Scenario B: Deactivating Detection Execution
To pause the rule entirely:
```yaml
deployment:
  enabled: false     # Rule is paused in the SIEM
  alerting: false
```

### Scenario C: Retiring a Rule (Decommissioning)
To decommission a rule while preserving its full history, context, and test vectors for audits, move its YAML envelope to the standardized `_archived/` directory:
```bash
mv rulesets/secops/custom/legacy_rule.yaml rulesets/secops/_archived/
git add rulesets/secops/
git commit -m "secops: retire legacy_rule to _archived"
```
Rules placed in any underscore-prefixed folder (e.g. `_archived/`, `_deprecated/`, `_templates/`) are automatically excluded from loading, linting, matrix exports, and GitOps sync operations.

---

## Recipe 9: Generating MITRE ATT&CK Matrices & Catalogs

### Objective
Export objective detection catalogs across formats (`table`, `csv`, `json`, `markdown`) and generate MITRE ATT&CK Enterprise v19.2 matrices and Navigator layers for coverage tracking and multi-engine gap analysis.

### Catalog Commands
```bash
# Display on-screen detection catalog table (default format)
graft export catalog

# Filter catalog to a specific engine
graft export catalog --engine secops

# Export machine-readable CSV for audit readiness and data pipelines
graft export catalog --format csv --out exports/rules.csv

# Export Markdown catalog for repository documentation or wikis
graft export catalog --format markdown --out docs/RULE_CATALOG.md

# Export structured JSON for external data lakes or dashboards
graft export catalog --format json --out exports/rules.json
```

### Threat Matrix & MITRE Navigator Commands
```bash
# View terminal table of MITRE ATT&CK technique coverage
graft export matrix --format table

# Filter matrix table by engine
graft export matrix --format table --engine secops

# Generate official MITRE ATT&CK Navigator v4.5 JSON layer (default greenish gradient: #008744)
graft export matrix --format navigator --out exports/enterprise_coverage.json

# Generate engine-scoped Navigator layer with a custom gradient color
graft export matrix --format navigator --engine secops --color "#4285F4" --out exports/secops_coverage.json
```

### Multi-Engine Gap Analysis in MITRE Navigator
When operating multi-engine topologies (e.g., Google SecOps for cloud telemetry alongside an EDR or identity security platform), evaluating visibility gaps requires combining individual coverage footprints into an aggregated analytical layer.

For detailed background and methodology, see Joe Lopes's foundational guide:
👉 **[Gap Analysis with MITRE Navigator](https://lopes.id/log/gap-analysis-mitre-navigator/)**

#### 1. Export Per-Engine Layers with Distinct Colors
Rather than hardcoding engine-to-color mappings, Graft empowers operators to select distinct gradient colors via `--color`:
```bash
# Export Google SecOps layer (e.g. blue)
graft export matrix --format navigator --engine secops --color "#4285F4" --out exports/secops.json

# Export auxiliary engine layer (e.g. green)
graft export matrix --format navigator --engine sentinel --color "#008744" --out exports/sentinel.json
```

Each generated layer scopes techniques to tactic shortnames (e.g. `initial-access`, `defense-impairment`) and sets `selectTechniquesAcrossTactics: false`. This ensures technique scores and annotations remain locked to their relevant tactic column without bleeding across unrelated columns.

Each technique in the layer is enriched with:
- `metadata`: Engine origin, matching rule names, live deployment status (`enabled`, `silent`, `disabled`), and whether runbooks are documented. (Experimental test vectors are intentionally omitted).
- `links`: Clickable relative links directly to the rule YAML source files.

#### 2. Combining Layers in MITRE Navigator
1. Navigate to the [MITRE ATT&CK Navigator Web App](https://mitre-attack.github.io/attack-navigator/).
2. Open each exported layer (`exports/secops.json` as Layer **`a`**, `exports/sentinel.json` as Layer **`b`**).
3. Click **"+" > Create Layer from Other Layers** to combine them using mathematical expressions:
   - **Combined Footprint (Union):** `max(a, b)` highlights all techniques covered by at least one engine.
   - **Redundant Defenses (Intersection):** `min(a, b)` highlights techniques covered by both engines simultaneously.
   - **Normalized Gap Analysis (1–5 Scale):** To flag single-engine dependencies as high-priority gaps while celebrating redundancy, apply the normalized scoring formula:
     ```text
     1 + 4 * (1 - (max(a, b) * (1 - min(a, b))))
     ```
     - **Score 1 (Low / Red / High Risk):** Single-engine coverage. If that engine goes down or fails, your defense has a blind spot.
     - **Score 5 (High / Green / Low Risk):** Multi-engine redundancy. Both platforms actively detect the adversary behavior.
     - **Score 0 / Unscored (White):** Total blind spot across all platforms.

### MITRE ATT&CK Enterprise v19.2 Taxonomy
Graft stays current with modern adversary tactics and techniques, pinning to ATT&CK Enterprise v19.2:
- **Stealth Tactic (`TA0005`):** In v19.2, MITRE renamed `TA0005` from "Defense Evasion" to "Stealth". The corresponding YAML tactic name is `stealth`.
- **Defense Impairment Tactic (`TA0112`):** Introduced in v19.2 to capture actions that disable, corrupt, or modify defenses. The corresponding YAML tactic name is `defense-impairment`.
- **Technique Revocations & Replacements:** Techniques revoked by MITRE are rejected by `graft lint`. For example, `T1562.001` (Disable or Modify Tools) was revoked in v19.2 and replaced by `T1685` under `defense-impairment`. Graft adopts the latest taxonomy forward.

### Objective Catalog Schema (14 Fields)
Every catalog export (`table`, `csv`, `json`, `markdown`) normalizes to 14 objective indicators:

| Field | Description | Source |
| :--- | :--- | :--- |
| `id` | Unique UUID string identifying the detection | Rule YAML `metadata.id` |
| `name` | Canonical slug identifier | Rule YAML `metadata.name` |
| `engine` | Target SIEM / engine identifier (e.g. `secops`) | Directory topology |
| `rule_type` | `custom` or `managed` | Directory taxonomy |
| `status` | Tri-state deployment health: `enabled`, `silent`, or `disabled` | Engine adapter evaluation |
| `description` | Summary of threat behavior detected | Rule YAML `metadata.description` |
| `mitre_attack` | Semicolon-delimited `TAxxxx:Tyyyy.zzz` pairs | Rule YAML `metadata.mitre` |
| `tags` | Semicolon-delimited operational tags | Rule YAML `metadata.tags` |
| `owners` | Accountable rule owners (`;` in CSV, `, ` in Markdown, list in JSON) | Rule YAML `metadata.owners` |
| `created_at` | Initial commit timestamp (ISO 8601) | Git commit history |
| `last_modified_at` | Most recent commit timestamp (ISO 8601) | Git commit history |
| `review_count` | Total number of revision commits | Git revision count |
| `contributor_count` | Number of distinct Git authors | Git commit history |
| `has_runbook` | Whether triage and response runbook is documented | Rule YAML `runbook` block |

> [!NOTE]
> **Why `priority`, `severity`, `alerting`, and `maturity` Are Omitted:**
> - **`priority` and `severity`** do not belong at detection authoring time: **Priority** belongs at **Triage time** (where queue ordering depends on live asset criticality and identity context), and **Severity** belongs at **Response time** (where incident impact is determined after triage).
> - Raw deployment fields (`alerting`, `enabled`, `run_frequency`) vary broadly by engine; Graft abstracts them into an engine-evaluated tri-state `status` (`enabled`, `silent`, `disabled`).
> - Static `maturity` labels rot into administrative toil and false security. Objective VCS lifecycle and review metrics provide verifiable indicators without synthetic score inflation.

---

## Recipe 10: Registering & Mapping a Vendor-Managed Rule

### Objective
Optionally register an enabled vendor-managed rule or ruleset from `rulesets/<engine>/managed/index.yaml` so its MITRE ATT&CK coverage, accountable owners, and SOC triage runbook appear in `graft export matrix` and `graft export catalog`.

### Step 1: Find the Managed Rule ID in `index.yaml`
Open [`rulesets/secops/managed/index.yaml`](../../rulesets/secops/managed/index.yaml) and copy the unique `id` of the curated ruleset you want to map (for example, `433faf9e-4d51-f284-c35b-009528ecff05` for `"GCTI Active Breach Network Indicators"`).

### Step 2: Scaffold the Registered Managed Rule
```bash
graft secops new gcti_active_breach_network_indicators --managed 433faf9e-4d51-f284-c35b-009528ecff05
```

### Step 3: Populate Metadata, MITRE & Runbook
Edit `rulesets/secops/managed/gcti_active_breach_network_indicators.yaml` (validated against `base_managed.schema.json`):
```yaml
metadata:
  id: "a4d89e12-3b77-4f08-9c61-82d47e910b3a"
  name: "gcti_active_breach_network_indicators"
  description: "Google Cloud Threat Intelligence network indicators from active breach investigations."
  owners:
    - "Cloud Security Operations"
  mitre:
    command-and-control:
      - "T1071"
      - "T1071.001"
  tags:
    - "gcti"
    - "curated"
    - "network"
  references:
    - "https://cloud.google.com/chronicle/docs/detection/cloud-threats-category"

managed:
  id: "433faf9e-4d51-f284-c35b-009528ecff05"

runbook:
  context: |
    Matches network telemetry against curated indicators of compromise (IoCs) maintained by GCTI.
  triage: |
    1. Inspect the matched indicator (domain, IP, or URI) and principal asset.
    2. Pivot on the principal asset across DNS, proxy, and process telemetry.
  response: |
    1. Isolate the affected host or workload if active C2 is confirmed.
    2. Block the indicator across perimeter firewall and DNS controls.

tests: []
```

### Step 4: Validate & Export
```bash
# Verifies schema, MITRE taxonomy, and 1-to-1 existence in managed/index.yaml
graft lint

# View the registered managed rule alongside custom rules (rule_type: managed)
graft export catalog
graft export matrix --format table
```

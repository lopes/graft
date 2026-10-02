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
11. [Recipe 11: Creating, Expiring & Retiring Reusable Datasets (`datasets/<name>.yaml`)](#recipe-11-creating-expiring--retiring-reusable-datasets-datasetsnameyaml)

---

## Recipe 1: Scaffolding a New Rule

### Objective
Create a new detection rule file with an auto-generated UUID, valid schema defaults, and an initial test vector skeleton (or a 4-block registered managed rule envelope via `--managed <id>`).

### Command
```bash
# Custom rule — Using the engine-specific command:
graft secops new gcp_service_account_key_created

# Custom rule — Or using the root command router:
graft new rule gcp_service_account_key_created --engine secops

# Registered managed rule — Link to a vendor ID in rulesets/secops/managed/index.yaml:
graft secops new gcti_breach_network_indicator_matched --managed 433faf9e-4d51-f284-c35b-009528ecff05
```

### Result
For custom rules, Graft creates `rulesets/secops/custom/gcp_service_account_key_created.yaml` with pre-populated `metadata`, `logic`, `deployment`, `runbook`, and `tests` blocks. When `--managed <id>` is supplied, Graft creates `rulesets/secops/managed/<rule_name>.yaml` with `metadata`, `managed`, `runbook`, and `tests: []`.

---

## Recipe 2: Authoring the 5-Block Envelope

### Objective
Fill out the scaffolded rule with realistic detection logic, operational controls, and attack taxonomy.

### Rule Template
```yaml
metadata:
  id: "b1d72370-5fa3-4cb8-a579-22a468d6f101"
  name: "gcp_service_account_key_created"
  description: "Long-lived user-managed GCP service account keys created."
  owners:
    - "Joe Lopes"
  mitre:
    persistence:
      - "T1098"
      - "T1098.001"
    privilege-escalation:
      - "T1078.004"
  tags:
    - "gcp"
    - "iam"
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
graft lint rulesets/secops/custom/gcp_service_account_key_created.yaml

# Output structured JSON for automation or pre-commit hooks
graft --json lint rulesets/secops/custom/gcp_service_account_key_created.yaml
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
graft secops verify rulesets/secops/custom/gcp_service_account_key_created.yaml

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
graft secops test rulesets/secops/custom/gcp_service_account_key_created.yaml

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

### Objective Catalog Schema (15 Fields)
Every catalog export (`table`, `csv`, `json`, `markdown`) normalizes to 15 objective indicators:

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
| `author` | Initial creator (author name of the earliest Git commit) | Git commit history (`--follow`) |
| `owners` | Accountable rule owners (`;` in CSV, `, ` in Table/Markdown, list in JSON) | Rule YAML `metadata.owners` |
| `owner_count` | Number of assigned accountable owners (`len(metadata.owners)`) | Rule YAML `metadata.owners` |
| `created_at` | Initial commit date normalized to UTC `YYYY-MM-DD` | Git commit history (`--follow`) |
| `last_modified_at` | Most recent commit date normalized to UTC `YYYY-MM-DD` | Git commit history (`--follow`) |
| `review_count` | Total number of revision commits across file renames | Git commit history (`--follow`) |
| `contributor_count` | Number of distinct Git author emails (case-insensitive) | Git commit history (`--follow`) |

> [!NOTE]
> **Why `priority`, `severity`, `alerting`, `has_runbook`, and `maturity` Are Omitted:**
> - **`priority` and `severity`** do not belong at detection authoring time: **Priority** belongs at **Triage time** (where queue ordering depends on live asset criticality and identity context), and **Severity** belongs at **Response time** (where incident impact is determined after triage).
> - **`has_runbook`** is omitted because the `runbook` block (`context`, `triage`, `response`) is strictly required and non-blank in all custom and registered managed rule schemas.
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
graft secops new gcti_breach_network_indicator_matched --managed 433faf9e-4d51-f284-c35b-009528ecff05
```

### Step 3: Populate Metadata, MITRE & Runbook
Edit `rulesets/secops/managed/gcti_breach_network_indicator_matched.yaml` (validated against `base_managed.schema.json`):
```yaml
metadata:
  id: "e8a1b7c3-4f92-41d0-9e65-28f19c047110"
  name: "gcti_breach_network_indicator_matched"
  description: "GCTI curated ruleset matching active breach priority network indicators."
  owners:
    - "Joe Lopes"
  mitre:
    command-and-control:
      - "T1071.001"
  tags:
    - "gcti"
    - "network"
  references:
    - "https://docs.cloud.google.com/chronicle/docs/detection/curated-detections"

managed:
  id: "433faf9e-4d51-f284-c35b-009528ecff05"

runbook:
  context: "Google Cloud Threat Intelligence (GCTI) Active Breach Priority Network Indicators detects outbound and inbound network telemetry matching high-confidence command-and-control (C2) domains and IP addresses observed in active intrusion campaigns."
  triage: |
    1. Identify the internal host or workload initiating or receiving the network connection.
    2. Inspect the matched GCTI indicator (domain or IP address), port, protocol, and process lineage.
    3. Correlate endpoint and DNS telemetry on the affected asset over the preceding 24 hours.
    4. Check if any other internal assets communicated with the same external infrastructure.
  response: |
    1. Isolate the affected host or workload if unauthorized C2 communication is confirmed.
    2. Block the malicious domain and IP address at perimeter firewalls and DNS resolvers.
    3. Capture volatile memory or disk artifacts and escalate to Incident Response.

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

---

## Recipe 11: Creating, Expiring & Retiring Reusable Datasets (`datasets/<name>.yaml`)

### Objective
Create a reusable, engine-agnostic string dataset (`datasets/<name>.yaml`) for authorized scanner or assessment IP addresses, set automatic expiration dates (`ttl:YYYY-MM-DD`) on temporary entries, reference it inside a YARA-L 2.0 detection rule (`%<name>.value`), and safely archive or delete it when no longer needed.

### Step 1: Scaffold the Dataset
Use a plural noun phrase (`<context>_<entity_plural>`) for the dataset name:
```bash
graft new dataset security_assessment_ips
```

### Step 2: Populate `metadata`, `values`, and Optional `ttl:YYYY-MM-DD` Expirations
Edit [`datasets/security_assessment_ips.yaml`](../../datasets/security_assessment_ips.yaml) (validated against [`base_dataset.schema.json`](../../src/graft/core/schemas/base_dataset.schema.json)). Append `ttl:YYYY-MM-DD` inside any inline `#` comment to automatically omit that entry after `YYYY-MM-DD` (UTC):
```yaml
metadata:
  name: "security_assessment_ips"
  description: "Authorized penetration testing and security assessment source IP addresses."
  owners:
    - "Detection Engineering"
  tags:
    - "network"
    - "pentest"
    - "suppression"
  references:
    - "https://lopes.id/log/detection-rules-netscan-portscan/"

values:
  - "192.0.2.10"  # External red team assessment jumpbox (TEST-NET-1) ttl:2026-12-31
  - "198.51.100.25"  # Authorized third-party pentest egress node (TEST-NET-2)
```

### Step 3: Reference `%<name>.value` in Detection Logic
In [`rulesets/secops/custom/multiple_hosts_scanned.yaml`](../../rulesets/secops/custom/multiple_hosts_scanned.yaml), reference the dataset's canonical `.value` column:
```yaml
logic: |
  events:
    $net.metadata.event_type = "NETWORK_CONNECTION"
    $net.principal.ip != ""
    $net.target.ip != ""
    not $net.principal.ip in %known_scanner_ips.value
    not $net.principal.ip in %security_assessment_ips.value
    $src_ip = $net.principal.ip
    $dst_ip = $net.target.ip

  match:
    $src_ip over 5m

  outcome:
    $unique_target_ip_count = count_distinct($dst_ip)

  condition:
    $net and $unique_target_ip_count > 10
```

### Step 4: Validate, Verify & Synchronize
```bash
# 1. Offline schema, ttl:YYYY-MM-DD syntax, and dataset cross-reference validation (<100ms)
graft lint

# 2. Dry-run YARA-L syntax (substitutes placeholder if dataset is not yet in SecOps)
graft secops verify rulesets/secops/custom/multiple_hosts_scanned.yaml

# 3. Preview and apply (synchronizes Datasets first, then Custom Rules)
graft secops diff --env production
graft secops apply --env production
```

### Step 5: Archiving & Deleting a Dataset Safely
Never delete a Data Table directly in the SIEM while rules still reference `%<name>.value`. Follow this sequence:
1. **Archive in Git:** Move the file to `datasets/_archived/`:
   ```bash
   mv datasets/security_assessment_ips.yaml datasets/_archived/
   ```
2. **Sync Deprecation:** Merge or run `graft secops apply --env production`. If the table exists on the SIEM, Graft clears its rows to `0` and updates its description to `"Deprecated on Graft"` so existing rules keep compiling without matching stale values.
3. **Remove Rule References:** Remove `%security_assessment_ips.value` from your rules and deploy.
4. **Delete on SIEM & Optional Git Cleanup:** Delete the `"Deprecated on Graft"` table in the SIEM console. Once deleted remotely (404), Graft ignores the archived file on future runs, and you may optionally delete `datasets/_archived/security_assessment_ips.yaml` from Git.


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

---

## Recipe 1: Scaffolding a New Rule

### Objective
Create a new detection rule file with an auto-generated UUID, valid schema defaults, and an initial test vector skeleton.

### Command
```bash
# Using the engine-specific command:
graft secops new gcp_iam_service_account_key_create

# Or using the root command router:
graft new rule gcp_iam_service_account_key_create --engine secops
```

### Result
Graft creates `rules/secops/custom/gcp_iam_service_account_key_create.yaml` with pre-populated `metadata`, `logic`, `deployment`, `runbook`, and `tests` blocks.

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
  authors:
    - "Detection Engineering <detection@company.com>"
  mitre:
    persistence:
      - "T1098"
      - "T1098.001"
    privilege_escalation:
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
graft lint rules/secops/custom/gcp_iam_service_account_key_create.yaml

# Output structured JSON for automation or pre-commit hooks
graft --json lint rules/secops/custom/gcp_iam_service_account_key_create.yaml
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
graft secops verify rules/secops/custom/gcp_iam_service_account_key_create.yaml

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
graft secops test rules/secops/custom/gcp_iam_service_account_key_create.yaml

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

### Scenario C: Retiring a Rule
To decommission a rule, delete its YAML envelope file from `rules/<engine>/custom/`:
```bash
git rm rules/secops/custom/legacy_rule.yaml
git commit -m "rules(secops): retire legacy_rule"
```
When merged to `main`, Graft's GitOps reconciler automatically detects the deletion and deprovisions the rule from the remote SIEM tenant.

---

## Recipe 9: Generating MITRE ATT&CK Matrices & Catalogs

### Commands
```bash
# View terminal ASCII table of current MITRE ATT&CK technique coverage
graft export matrix --format table

# Generate an ATT&CK Navigator v4.5 JSON layer for heatmaps
graft export matrix --format navigator --out layers/enterprise_coverage.json

# Export a Markdown rule catalog with Git author attribution and deployment status
graft export catalog --format markdown --out docs/RULE_CATALOG.md

# Export machine-readable CSV for GRC and audit compliance
graft export catalog --format csv --out exports/rules.csv
```

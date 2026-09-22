# Engine Adoption & Lifecycle Guide

> **Bootstrapping Detection-as-Code from Live SIEM to Authoritative Source of Truth**  
> **Target Engines:** Google SecOps (Chronicle) & Pluggable SIEM Adapters  
> **Core Concept:** The Brownfield Ingestion, Baseline Enrichment, and Source-of-Truth Cutover Lifecycle

---

## 1. The Brownfield Adoption Challenge

When adopting Detection-as-Code (DaC) in an enterprise, the detection engineering environment is almost never greenfield. The SIEM instance is already live, actively monitoring production telemetry, and populated with:
- **Vendor-Managed Content:** Curated rule sets (e.g., Google Cloud Curated Rule Sets) with operational precision levels (`PRECISE` vs `BROAD`), alert routing, and production tuning exclusions.
- **Custom Detection Rules:** Bespoke organizational detection rules authored directly in the SIEM web console or deployed via legacy scripts.

If an engineering team adopts Graft with an empty repository and immediately declares Git as the authoritative Source of Truth (SoT), running forward synchronization (`graft secops apply --all`) would either fail to discover existing rules or risk destructive deletion if automated pruning were enabled.

To solve this, Graft treats an engine's lifecycle not as a static assumption, but as a formal **three-epoch progression**.

---

## 2. The Three-Epoch Engine Lifecycle

```mermaid
flowchart TD
    subgraph E1["Epoch 1: Discovery & Reverse Sync (SIEM = Temporary SoT)"]
        direction TB
        SIEM["<b>Live SecOps Tenant</b><br/>• Active Curated Rule Sets & Exclusions<br/>• Active Custom YARA-L Rules & Deployments"]
        PULL["<code>graft secops pull --env production</code><br/><i>(Reverse Synchronization)</i>"]
        SIEM --> PULL
        PULL --> MAN["<code>rulesets/secops/managed.yaml</code>"]
        PULL --> CUST["<code>rulesets/secops/custom/*.yaml</code>"]
    end

    subgraph E2["Epoch 2: Baseline Enrichment & Cutover"]
        direction TB
        ENRICH["<b>Operator Review & Enrichment</b><br/>• Document Incident Response Runbooks<br/>• Map MITRE ATT&CK Techniques<br/>• Add Synthetic UDM Test Vectors<br/>• Verify via <code>graft lint</code>"]
        COMMIT["<b>Baseline Cutover Commit</b><br/><code>git commit -m 'secops: import detection baseline'</code><br/><code>git push origin main</code>"]
        MAN --> ENRICH
        CUST --> ENRICH
        ENRICH --> COMMIT
    end

    subgraph E3["Epoch 3: Steady-State GitOps (Git = Sole Authoritative SoT)"]
        direction TB
        PR["PR Validation Gates<br/>(Ruff, Mypy, Pytest, verifyRuleText, Replay)"]
        MERGE["Merge to Mainline<br/>(Automated Deploy to Production)"]
        DRIFT["Scheduled Drift Reconciliation<br/><code>graft secops diff/apply --all</code>"]
        OVERWRITE["<b>Authoritative Healing</b><br/>Out-of-band console edits overwritten"]
        AUDIT["<b>Tamper-Evident Audit Trail</b><br/>Git blame + CI run execution logs"]

        COMMIT --> PR
        PR --> MERGE
        MERGE --> DRIFT
        DRIFT --> OVERWRITE
        OVERWRITE --> AUDIT
    end

    E1 --> E2 --> E3
```

---

## 3. Epoch 1: Discovery & Reverse Sync

In Epoch 1, the live SIEM instance is recognized as the **temporary initial Source of Truth**.

### 1. Reverse Synchronization Command

Running `graft <engine> pull` extracts the complete live detection posture from the target tenant:

```bash
# Pull both custom rules and vendor-managed content from production
uv run graft secops pull --env production
```

Alternatively, you can target individual subsystems:

```bash
# Pull custom YARA-L detection rules only
uv run graft secops pull --target custom --env production --out-dir rulesets/secops/custom

# Pull vendor-managed curated content manifest only
uv run graft secops pull --target managed --env production --out-manifest rulesets/secops/managed.yaml

# Force overwrite existing local files without confirmation prompts
uv run graft secops pull --env production --force
```

### 2. How Managed Content Is Ingested

When pulling managed content:
1. Graft queries the Chronicle Curated Rule Sets API (`curatedRuleSets`, `curatedRuleSetDeployments`, and `ruleExclusions`).
2. It resolves category UUIDs to display names (e.g., `Cloud Threats`, `Linux Threats`).
3. It captures deployment precision (`PRECISE` or `BROAD`), enabled/alerting toggles, and all active UDM exclusion filters (`findingsRefinements`).
4. It serializes this unified posture into [`rulesets/secops/managed.yaml`](file:///usr/local/google/home/joelopes/Projects/graft/rulesets/secops/managed.yaml), conforming to [`src/graft/engines/secops/schemas/managed.schema.json`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/engines/secops/schemas/managed.schema.json).

### 3. How Custom Rules Are Ingested

When pulling custom rules:
1. Graft invokes `SecOpsDeployerAdapter.list_rules()` to fetch rule inventory (`GET rules?view=FULL`) and deployment states (`GET rules/-/deployments`).
2. The deconstruction compiler ([`deconstruct_yaral_rule`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/engines/secops/compiler.py#L53)):
   - Sanitizes rule display names into valid snake_case identifiers matching `^[a-z0-9_]+$`.
   - Normalizes server identifiers (`ru_<uuid>`) into valid RFC 4122 UUIDs for `metadata.id`.
   - Extracts embedded metadata (`description`, `author`) from the rule's `meta:` block.
   - Preserves clean YARA-L logic (`events:`, `match:`, `condition:`) in the envelope's `logic` block.
3. Graft populates standard default runbook sections (`context`, `triage`, `response`) so that the resulting envelopes immediately pass strict schema validation.
4. Each rule is saved to `rulesets/secops/custom/<rule_name>.yaml`. Existing files are protected against accidental overwrites unless `--force` is supplied.

---

## 4. Epoch 2: Baseline Enrichment & Cutover

Imported rules reflect what was running in the SIEM console. However, bare SIEM rules often lack operational context, incident response procedures, MITRE ATT&CK taxonomy tags, and synthetic test vectors.

### 1. Enrichment Checklist

Before committing the baseline to version control, detection engineers review and enrich the envelopes:

- **Runbooks:** Replace default placeholder triage and response playbooks with verified operational steps:
  ```yaml
  runbook:
    context: "Detects unauthorized creation of service account keys in production projects."
    triage: |
      1. Inspect principal email executing the Key creation.
      2. Check whether principal is an authorized Terraform CI/CD pipeline.
      3. Verify project IAM policy binding.
    response: |
      1. Delete unauthorized service account key immediately via gcloud IAM.
      2. Disable compromised user or service account credentials.
  ```
- **MITRE ATT&CK Mappings:** Map tactics and techniques:
  ```yaml
  mitre:
    persistence:
      - "T1098.001"
    privilege_escalation:
      - "T1078.004"
  ```
- **Synthetic Test Vectors:** Add deterministic UDM events and expected match counts:
  ```yaml
  tests:
    - id: "match_service_account_key_create"
      description: "Fires when admin_service.CreateServiceAccountKey is invoked"
      expect: 1
      events:
        - timestamp: "2026-09-17T12:00:00Z"
          payload:
            metadata:
              event_type: "USER_RESOURCE_MUTATION"
              product_event_type: "google.iam.admin.v1.CreateServiceAccountKey"
  ```

### 2. Offline Validation

Validate the entire catalog offline against Draft 2020-12 schemas and bundled MITRE ATT&CK data:

```bash
uv run graft lint
```

Ensure all imported custom rules and the managed manifest return `0 errors`.

### 3. The Baseline Cutover Commit

Once validated, commit the baseline to Git:

```bash
git add rulesets/
git commit -m "secops: import initial detection baseline from production tenant"
git push origin main
```

**The Cutover Declaration:** Merging this baseline commit into `main` marks the official cutover point. From this moment onward, **Git is formally declared the sole, authoritative Source of Truth (SoT)**.

---

## 5. Epoch 3: Steady-State GitOps Operations

Once the cutover is complete, the direction of authority permanently reverses: **Git drives the SIEM; the SIEM never drives Git.**

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Detection Engineer
    participant PR as GitHub PR
    participant CI as GitHub Actions
    participant SIEM as Google SecOps Tenant

    Note over Analyst,SIEM: Normal Day-to-Day Change
    Analyst->>PR: Propose rule edit or exclusion in branch
    PR->>CI: Trigger pr-validation.yml
    CI->>CI: Ruff, Mypy, Pytest, Graft Lint
    CI->>SIEM: Dry-run syntax (verifyRuleText)
    CI->>SIEM: Staging quarantine replay test
    CI-->>PR: Green verification check
    Analyst->>PR: Merge PR to main

    Note over CI,SIEM: Authoritative Production Apply
    PR->>CI: Trigger deploy-production.yml
    CI->>SIEM: graft secops apply
    SIEM-->>CI: Custom rules updated in-place (new revision)
    SIEM-->>CI: Managed deployments & exclusions synchronized

    Note over Analyst,SIEM: Out-of-Band Console Drift Occurs
    Analyst->>SIEM: Console user disables rule directly in UI
    CI->>SIEM: Periodic drift scan (graft secops diff --all)
    SIEM-->>CI: Drift detected (exit code 2)
    CI->>SIEM: Authoritative reconciliation (graft secops apply --all)
    SIEM-->>CI: Rule re-enabled in-place to match Git
    CI->>CI: Structured audit log emitted
```

### 1. Drift Governance & Self-Healing Modes

Graft provides two operating modes to manage out-of-band modifications made directly in the SIEM web console:

- **Scoped Reconciliation (Default):**
  Commands like `graft secops diff` and `graft secops apply` inspect Git diffs (`HEAD~1` or branch diff) and evaluate only rules modified in the current change scope. This keeps daily CI/CD operations fast and lightweight.
- **Full Catalog Reconciliation (`--all`):**
  Running `graft secops diff --all` or `graft secops apply --all` ignores Git change history and evaluates every single rule and managed deployment against the live tenant:
  - **Drift Discovery:** `graft secops diff --all --env production` detects discrepancies and exits with code `2`.
  - **Authoritative Healing:** `graft secops apply --all --env production` overwrites any console edits, reconciling the tenant back to the exact version declared in Git.

### 2. Tamper-Evident Audit Trail

Every state change executed by Graft is recorded across two independent audit layers:
1. **Version Control Audit:** Every modification, addition, exclusion, or retirement is backed by a Scoped Commit, reviewer approval, and Git blame history.
2. **Execution Logs:** The CLI emits structured JSON and machine-parseable stdout detailing the exact rule revisions, previous states, and updated states:
   ```json
   {
     "custom": {
       "applied": true,
       "has_changes": true,
       "created": 0,
       "updated": 1
     },
     "managed": {
       "applied": true,
       "has_changes": false
     }
   }
   ```
   In CI/CD pipelines, these logs are retained as immutable build artifacts for compliance and audit requirements.

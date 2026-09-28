# Detection Rule Authoring Guide

Graft standardizes all custom detection engineering around a declarative **5-Block Envelope** YAML format. Every rule file combines detection logic with metadata, deployment settings, operational runbooks, and synthetic replay test vectors in a single reviewable unit.

---

## 1. The 5-Block Envelope Structure

```mermaid
flowchart TD
    ROOT["Rule Envelope (.yaml)"]
    ROOT --> B1["<b>1. metadata</b><br/>ID, Name, Authors, MITRE, Tags, References"]
    ROOT --> B2["<b>2. logic</b><br/>Engine-Native Query String (e.g. YARA-L 2.0)"]
    ROOT --> B3["<b>3. deployment</b><br/>Enabled, Alerting, Run Frequency (live/hourly/daily)"]
    ROOT --> B4["<b>4. runbook</b><br/>Context, Triage Checklist, Incident Response Steps"]
    ROOT --> B5["<b>5. tests</b><br/>Synthetic UDM Events & Expected Match Count"]
```

### Block 1: `metadata`
Core identification and threat taxonomy mapping.

- `id` *(UUID string, required)*: Globally unique identifier (v4 UUID format).
- `name` *(string, required)*: Unique snake_case rule identifier (`^[a-z0-9_]+$`, max 64 chars).
- `description` *(string, required)*: Plain-text explanation of the detection objective (max 128 chars).
- `authors` *(list of strings, optional)*: Rule authors and engineering teams.
- `mitre` *(mapping of tactic to techniques, optional)*: MITRE ATT&CK Enterprise taxonomy mapping. Must use valid lowercase tactic names (`initial_access`, `execution`, `persistence`, etc.) and real technique IDs (`T1566.002`, `T1098.001`). Validated against pre-indexed matrix during linting.
- `tags` *(list of strings, optional)*: Categorical labels (e.g., `google_workspace`, `gcp`, `phishing`).
- `references` *(list of strings, optional)*: Canonical URLs to threat research, documentation, or blog posts.

> [!NOTE]
> **Why Static `status` / `maturity` Fields Are Intentionally Omitted:**
> In threat detection engineering, static enum fields like `status: production`, `maturity: mature`, or `lifecycle: testing` inevitably rot. Teams rarely remember to update them when rules evolve, creating administrative toil and a false sense of coverage security ("security theater").
>
> Graft rejects hardcoded maturity labels. Instead, maturity is treated as an **empirical, measurable property** reflected in objective indicators:
> - **VCS Lifecycle:** First committed date (`created_at`) and latest revision date (`last_modified_at`).
> - **Peer Scrutiny:** Total revision history (`review_count`) and breadth of peer review (`contributor_count`).
> - **Operational Context:** Documented operational triage procedures (`has_runbook`), unified ATT&CK mappings (`mitre_attack`), and tri-state deployment health (`status: enabled | silent | disabled`).
>
> Graft also deliberately refuses to compute an arbitrary synthetic score (e.g. 0–100) from repo data alone ("no bullshit"). A rule with 10 commits might still produce 10,000 false positives in production. Instead, Graft surfaces these objective indicators via `graft export catalog` so detection engineering teams can join them with external SIEM/SOAR runtime metrics (true-positive rate, precision, alert volume, MTTR) to measure true health.

### Block 2: `logic`
Engine-native query logic. For Google SecOps, this contains YARA-L 2.0 sections (`events:`, `match:`, `outcome:`, `condition:`). Graft automatically synthesizes the `rule <name> { meta: ... }` wrapper when sending to Chronicle APIs.

### Block 3: `deployment`
Operational controls governing how the rule runs in the target engine.

- `enabled` *(boolean, required)*: Whether the rule is actively executing against telemetry.
- `alerting` *(boolean, required)*: Whether matches produce SOC alerts or silent detections.
- `run_frequency` *(string, required)*: Execution cadence (`live`, `hourly`, `daily`, `unspecified`).

### Block 4: `runbook`
Actionable documentation embedded directly alongside detection logic.

- `context` *(string, required)*: Background on the attack technique, adversary objectives, and false positive considerations.
- `triage` *(string, required)*: Step-by-step checklist for the SOC analyst to investigate alerts.
- `response` *(string, required)*: Remediation and containment procedures if malicious activity is confirmed.

### Block 5: `tests`
Synthetic replay test fixtures for automated validation.

> [!NOTE]
> **Experimental Capability:** Synthetic replay tests in rule envelopes are an experimental capability. While schema-validated and parsed by Graft core models, dynamic cloud replay execution requires dedicated staging instances and is subject to SIEM API availability.

- `id` *(string, required)*: Unique test vector identifier (`^[a-z0-9_]+$`).
- `description` *(string, required)*: Objective of this test case.
- `expect` *(integer, required)*: Expected number of detection matches (e.g., `1` for positive tests, `0` for negative tests).
- `events` *(list of objects, required)*: Synthetic event payloads with `timestamp` (ISO 8601) and engine-native event `payload` (e.g. UDM JSON).

---

## 2. Rule Identification & Uniqueness Scoping

To maintain data integrity across multi-engine deployments, audit catalogs, and SIEM migrations, Graft enforces a dual-tier uniqueness model:

```mermaid
flowchart TD
    subgraph RepoScope["Graft Repository Scope (Global)"]
        ID["<b>metadata.id (Global Uniqueness)</b><br/>Must be unique across ALL engines in the repository<br/><i>e.g. A SecOps rule ID cannot collide with a CrowdStrike rule ID</i>"]
    end

    subgraph EngineScope["Engine Scope (Per Engine)"]
        NAME["<b>metadata.name (Engine-Scoped Uniqueness)</b><br/>Must be unique within the specific engine directory (rulesets/&lt;engine&gt;/custom/)<br/><i>e.g. Rules in different engines CAN share the same technical name</i>"]
    end
```

### 1. Global Scope: `metadata.id`
- **Constraint:** Must be a valid v4 UUID string (`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`) and strictly unique across the entire Graft codebase.
- **Rationale:** The `metadata.id` represents the immutable, canonical identity of the detection concept within the enterprise. It is referenced by audit logs, compliance exports, ATT&CK Navigator heatmaps, and cross-platform SIEM migration tooling. No two rule files in the repository may share an `id`, even if they target completely different detection engines (e.g., Google SecOps vs. CrowdStrike Falcon).

### 2. Engine Scope: `metadata.name`
- **Constraint:** Must be a lowercase alphanumeric snake_case slug (`^[a-z0-9_]+$`, max 64 characters) and unique within the target engine (`rulesets/<engine>/custom/`).
- **Rationale:** The `metadata.name` serves as the native SIEM identifier (such as the YARA-L rule identifier `rule <name> { ... }` in Chronicle or the detection title in other platforms). While two rules in the same engine cannot share a name (which would create an overwrite collision on the tenant), rules across different engines **can** share the same `name` (e.g. `rulesets/secops/custom/gcp_iam_service_account_key_create.yaml` and a corresponding `rulesets/crowdstrike/custom/gcp_iam_service_account_key_create.yaml`).

### 3. Automated Verification
Rule uniqueness is enforced automatically during:
- Local rule linting (`graft lint`).
- Git pre-commit hooks (`.githooks/pre-commit`).
- Pull request CI/CD gates (`.github/workflows/pr-validation.yml`).

---

## 3. Reference Rule Example (Google Workspace)

Below is an authentic reference rule implemented in [`rulesets/secops/custom/workspace_nrd_possible_phishing.yaml`](../../rulesets/secops/custom/workspace_nrd_possible_phishing.yaml):

```yaml
metadata:
  id: "b1d72370-5fa3-4cb8-a579-22a468d6f101"
  name: "workspace_nrd_possible_phishing"
  description: "User opened an email from a domain created within the last 7 days."
  authors:
    - "Joe Lopes <lopes.id>"
    - "Detection Engineering"
  mitre:
    initial_access:
      - "T1566.002"
  tags:
    - "google_workspace"
    - "email"
    - "nrd"
    - "phishing"
    - "whois"
  references:
    - "https://lopes.id/log/high-fidelity-nrd-detections/"
    - "https://support.google.com/a/answer/12384955"

logic: |
  events:
    $mail.metadata.event_type = "EMAIL_TRANSACTION"
    $mail.metadata.product_event_type = "2"
    strings.extract_domain($mail.network.email.from) = $domain

    $whois.graph.entity.domain.name = $domain
    $whois.graph.metadata.entity_type = "DOMAIN_NAME"
    $whois.graph.metadata.vendor_name = "WHOIS"
    $whois.graph.metadata.product_name = "WHOISXMLAPI Simple Whois"
    $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
    $whois.graph.entity.domain.creation_time.seconds > 0

    // domain was created in the last 7 days: 7 * 24 * 60 * 60 = 604800 seconds
    604800 > timestamp.current_seconds() - $whois.graph.entity.domain.creation_time.seconds

  match:
    $domain over 1h

  outcome:
    $risk_score = 65
    $created_at = array_distinct(timestamp.get_date($whois.graph.entity.domain.creation_time.seconds))
    $sender = array_distinct($mail.network.email.from)
    $recipients = array_distinct($mail.network.email.to)
    $num_messages = count($mail.network.email.mail_id)

  condition:
    $mail and $whois

deployment:
  enabled: true
  alerting: true
  run_frequency: "live"

runbook:
  context: |
    Adversaries frequently register new domains and immediately weaponize them in spear-phishing campaigns before reputation feeds and web categorization tools index them. Correlating Google Workspace message open events with domain registration timestamps isolates zero-day phishing infrastructure.
  triage: |
    1. Identify recipient user account and workstation coordinates.
    2. Review email subject, sender domain WHOIS registrar, and message attachments.
    3. Check if recipient clicked any hyperlinks or submitted credentials.
    4. Search email transaction logs across the organization for other recipients of the same domain.
  response: |
    1. Quarantine the suspicious message across all Workspace inboxes.
    2. Add the sender domain to global perimeter and email blocklists.
    3. If credentials were provided or malicious payload downloaded, initiate host containment and session revocation.

tests:
  - id: "match_opened_nrd_email"
    description: "Triggers when a user opens an email originating from a newly registered domain"
    expect: 1
    events:
      - timestamp: "2026-09-17T14:00:00Z"
        payload:
          metadata:
            event_type: "EMAIL_TRANSACTION"
            product_event_type: "2"
          network:
            email:
              from: "security-update@login-verify-account.top"
              to:
                - "employee@corp.example.com"
              mail_id: "msg-workspace-98214"
      - timestamp: "2026-09-17T14:00:05Z"
        payload:
          graph:
            metadata:
              entity_type: "DOMAIN_NAME"
              vendor_name: "WHOIS"
              product_name: "WHOISXMLAPI Simple Whois"
              source_type: "GLOBAL_CONTEXT"
            entity:
              domain:
                name: "login-verify-account.top"
                creation_time:
                  seconds: 1773700000

  - id: "ignore_standard_unopened_email"
    description: "Verifies no alert triggers when email is received but not opened"
    expect: 0
    events:
      - timestamp: "2026-09-17T14:10:00Z"
        payload:
          metadata:
            event_type: "EMAIL_TRANSACTION"
            product_event_type: "1"
          network:
            email:
              from: "newsletter@trusted-vendor.com"
              to:
                - "employee@corp.example.com"
              mail_id: "msg-workspace-98215"
```

---

## 4. Scaffolding & Offline Validation

### Scaffolding a New Rule

Use `graft secops new` or `graft new rule` to bootstrap a complete 5-block envelope with schema defaults and unique UUID:

```bash
# SecOps engine shortcut (recommended):
graft secops new gcp_cloud_storage_public_bucket

# Engine-agnostic dispatcher:
graft new rule gcp_cloud_storage_public_bucket --engine secops

# Specify a custom target path:
graft secops new gcp_cloud_storage_public_bucket --out rulesets/secops/custom/tier1/storage.yaml
```

The generated file includes pre-populated runbook sections, deployment defaults (`enabled: false`, `alerting: false`, `run_frequency: "live"`), and a template test fixture.

### Validating Rules Offline

Graft's linter validates JSON Schema constraints and verifies MITRE techniques against the bundled ATT&CK matrix in milliseconds without network calls:

```bash
# Lint specific rule
graft lint rulesets/secops/custom/workspace_nrd_possible_phishing.yaml

# Lint entire repository
graft lint

# Fail immediately on first error
graft lint --fail-fast

# Output structured JSON diagnostics for CI/CD pipelines
graft --json lint
```

#### Example Linter Output:
```text
[PASS] rulesets/secops/custom/workspace_nrd_possible_phishing.yaml
[PASS] rulesets/secops/custom/gcp_iam_service_account_key_create.yaml
[PASS] rulesets/secops/managed.yaml
Checked 4 rules across 1 engines. All rules passed validation.
```

When schema constraints or invalid MITRE tactics/techniques are detected:
```text
[FAIL] rulesets/secops/custom/broken_rule.yaml:
  - Schema Error: 'run_frequency' is a required property in 'deployment'
  - MITRE Error: Unknown technique 'T9999.001' under tactic 'initial_access'
Linting failed with 2 error(s).
```

### Optional: Git Pre-Commit Hook

To catch schema violations, invalid YAML, unknown MITRE ATT&CK techniques, and code formatting errors before creating commits, enable the repository's native pre-commit hook:

```bash
git config core.hooksPath .githooks
```

Whenever you run `git commit`, the hook executes `ruff format --check`, `ruff check`, `graft lint`, and `pytest tests/unit` in sub-second time. To disable it at any time:

```bash
git config --unset core.hooksPath
```

---

## 5. Decommissioning Rules & Underscore Convention

When a detection is retired, superseded, or taken offline, **do not hard-delete the file**. Deleting rules destroys version history context, runbook guidance, and synthetic test payloads that may be needed for historic incident triage, post-mortems, or compliance audits.

### The `_archived` Standard

Instead, move decommissioned rules into the standardized `_archived/` directory under that ruleset:

```bash
# Decommission a rule by moving it to _archived/
mv rulesets/secops/custom/workspace_nrd_possible_phishing.yaml rulesets/secops/_archived/
git add rulesets/secops/
git commit -m "secops: decommission workspace_nrd_possible_phishing to _archived"
```

### The Underscore (`_`) Exclusion Rule

Graft's rule loader and linter automatically ignore **any directory or file starting with an underscore (`_`)** within `rulesets/<engine>/`. 

This provides operators with flexible organizational options:
- `rulesets/<engine>/_archived/`: Standardized resting place for decommissioned or obsolete rules.
- `rulesets/<engine>/_deprecated/`: Alternative folder for rules pending planned sunset or migration.
- `rulesets/<engine>/_templates/`: Reusable rule scaffolding templates or partial snippets.
- `rulesets/<engine>/_drafts/`: Work-in-progress detection experiments not yet ready for linting or CI/CD gates.

Rules located in underscore-prefixed directories are completely skipped during:
- Rule discovery and loading (`load_rules_for_engine`).
- Schema and MITRE taxonomy linting (`graft lint`).
- Threat coverage matrix generation (`graft export matrix`).
- Visibility catalog exports (`graft export catalog`).
- GitOps reconciliation and deployment (`graft <engine> diff / apply`).


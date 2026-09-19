# Visibility, Threat Matrix & Catalog Tooling

Graft turns detection repositories into high-visibility threat coverage assets. Security leadership, SOC managers, and compliance auditors can assess coverage, review authorship, and export catalogs directly from the command line.

---

## 1. MITRE ATT&CK Matrix & Navigator Export

Graft aggregates technique mappings across all rules (custom detections and vendor-managed content) and generates coverage reporting.

```mermaid
flowchart LR
    RULES["Rule Repository<br/>• Custom 5-Block Envelopes<br/>• Managed Manifest Exclusions"] --> EXTRACT["<b>Matrix Aggregator</b><br/><code>src/graft/core/matrix.py</code>"]
    EXTRACT --> TABLE["Terminal Table<br/><code>--format=table</code>"]
    EXTRACT --> NAV["ATT&CK Navigator v4 JSON<br/><code>--format=navigator</code>"]

    NAV --> NAV_UI["https://mitre-attack.github.io/attack-navigator/<br/>Visual heatmaps & coverage gap analysis"]
```

### 1. Terminal Table Summary
View an immediate ASCII breakdown of covered techniques, associated tactics, and rule counts:

```bash
graft export matrix --format table
```

**Example Output:**
```text
MITRE ATT&CK Detection Matrix (Total Rules: 3 | Covered Techniques: 4)
==========================================================================================
Technique ID    Technique Name                   Rules   Rules / Detections
------------------------------------------------------------------------------------------
T1078.004       Cloud Accounts                   1       gcp_storage_iam_public_access...
T1098.001       Additional Cloud Credentials     1       gcp_iam_service_account_key_c...
T1562.001       Disable or Modify Tools          1       gcp_storage_iam_public_access...
T1566.002       Spearphishing Link               1       workspace_nrd_possible_phishing
------------------------------------------------------------------------------------------
```

### 2. Official ATT&CK Navigator v4 Layer Export
Generate JSON layers adhering to the MITRE ATT&CK Navigator specification (version 4.5) with coverage scores, color gradients, and rule annotations:

```bash
graft export matrix --format navigator --out layers/graft_coverage.json
# or directly via the navigator alias:
graft export navigator --out layers/graft_coverage.json
```

Import `layers/graft_coverage.json` directly into the [MITRE ATT&CK Navigator Web App](https://mitre-attack.github.io/attack-navigator/) to visualize detection coverage heatmaps, identify visibility gaps, and present metrics to stakeholders.

---

## 2. Git Blame & Author Attribution

Graft tracks the provenance of every detection rule without external Git libraries. Using Python's standard library `subprocess`, the attribution service extracts:

- **Creation Author & Timestamp:** Determined via `git log --diff-filter=A --follow --format=%an|%aI`.
- **Last Modified Author & Timestamp:** Extracted via `git log -n 1 --format=%an|%aI`.
- **Commit Revision Count:** Extracted via `git rev-list --count HEAD`.
- **Offline / Untracked Fallback:** Automatically falls back to `"Unknown"` and rule YAML metadata if files are uncommitted or executed in environments lacking Git history (e.g. Docker containers).

---

## 3. Rule Catalog Generation

Export comprehensive detection catalogs enriched with deployment status, run frequencies, MITRE techniques, and Git author attribution.

### Markdown Catalog (`--format=markdown`)
Ideal for automated documentation generation and GitHub wiki pages:

```bash
graft export catalog --format=markdown --out docs/RULE_CATALOG.md
```

| Rule Name | Engine | Type | Status | Run Frequency | MITRE Techniques | Author | Last Updated |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `gcp_iam_service_account_key_create` | secops | custom | production | live | T1098.001 | Cloud Security Operations | 2026-09-17 |
| `gcp_storage_iam_public_access_granted` | secops | custom | production | live | T1078.004, T1562.001 | Cloud Security Operations | 2026-09-17 |
| `workspace_nrd_possible_phishing` | secops | custom | production | live | T1566.002 | Joe Lopes <lopes.id> | 2026-09-17 |

### CSV Catalog (`--format=csv`)
Generate spreadsheet-ready exports for compliance tracking and executive reporting:

```bash
graft export catalog --format=csv --out exports/detection_catalog.csv
```

CSV exports contain: `id, name, engine, rule_type, status, severity, description, mitre_tactics, mitre_techniques, tags, author, created_at, last_modified_at, run_frequency, enabled, alerting`.

### JSON Catalog (`--format=json`)
Structured JSON for feeding security data lakes or internal developer portals:

```bash
graft export catalog --format=json
```

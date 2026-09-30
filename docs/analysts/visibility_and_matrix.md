# Visibility, Threat Matrix & Catalog Tooling

Graft turns detection repositories into high-visibility threat coverage assets. Security leadership, SOC managers, and compliance auditors can assess coverage, verify operational ownership, and export catalogs directly from the command line.

---

## 1. MITRE ATT&CK Enterprise v19.2 Matrix & Navigator Export

Graft aggregates technique mappings across all rules (custom detections and vendor-managed content) and generates coverage reporting pinned to MITRE ATT&CK Enterprise v19.2.

```mermaid
flowchart LR
    RULES["Rule Repository<br/>• Custom 5-Block Envelopes (custom/*.yaml)<br/>• Registered Managed Rules (managed/&lt;rule&gt;.yaml)"] --> EXTRACT["<b>Matrix Aggregator</b><br/><code>src/graft/core/matrix.py</code>"]
    EXTRACT --> TABLE["Terminal Table<br/><code>--format=table</code>"]
    EXTRACT --> NAV["ATT&CK Navigator v4.5 JSON<br/><code>--format=navigator</code>"]

    NAV --> NAV_UI["https://mitre-attack.github.io/attack-navigator/<br/>Visual heatmaps & coverage gap analysis"]
```

### 1. Terminal Table Summary
View an immediate ASCII breakdown of covered techniques, associated tactics, and rule counts:

```bash
graft export matrix --format table
# or filtered by engine:
graft export matrix --format table --engine secops
```

**Example Output:**
```text
MITRE ATT&CK Detection Matrix (Total Rules: 3 | Covered Techniques: 4)
==========================================================================================
Technique ID    Technique Name                   Rules   Rules / Detections
------------------------------------------------------------------------------------------
T1078.004       Cloud Accounts                   1       gcp_storage_iam_public_access...
T1098.001       Additional Cloud Credentials     1       gcp_iam_service_account_key_c...
T1685           Disable or Modify Tools          1       gcp_storage_iam_public_access...
T1566.002       Spearphishing Link               1       workspace_nrd_possible_phishing
------------------------------------------------------------------------------------------
```

### 2. Official ATT&CK Navigator v4.5 Layer Export
Generate JSON layers adhering to the MITRE ATT&CK Navigator specification (version 4.5) with coverage scores, customizable gradient colors, and rich rule annotations:

```bash
# Export unified catalog layer (default greenish gradient: #008744)
graft export matrix --format navigator --out exports/graft_coverage.json

# Export engine-scoped layer with custom gradient color
graft export matrix --format navigator --engine secops --color "#4285F4" --out exports/secops_coverage.json
```

Import `exports/graft_coverage.json` directly into the [MITRE ATT&CK Navigator Web App](https://mitre-attack.github.io/attack-navigator/) to visualize detection coverage heatmaps, identify visibility gaps, and present metrics to stakeholders.

### 3. Multi-Engine Gap Analysis in MITRE Navigator
Operators managing hybrid detection platforms (e.g. Google SecOps and endpoint security) can export distinct layers per engine using `--engine <name>` and `--color <hex>`, then leverage Navigator's layer combination arithmetic for automated gap analysis.

For an in-depth breakdown of Navigator layer expressions and visual gap analysis, see:
👉 **[Gap Analysis with MITRE Navigator](https://lopes.id/log/gap-analysis-mitre-navigator/)**

Each technique in the exported layer is scoped strictly to its tactic shortname (e.g. `initial-access`, `defense-impairment`) with `selectTechniquesAcrossTactics: false`, ensuring scores remain locked to their appropriate tactic column. Combining layers using Navigator's **Create Layer from Other Layers** feature enables:
- **Redundancy Evaluation (`min(a, b)`):** Highlights techniques defended by multiple engines simultaneously.
- **Combined Coverage (`max(a, b)`):** Surfaces the complete detection footprint.
- **Normalized Gap Analysis (`1 + 4 * (1 - (max(a, b) * (1 - min(a, b))))`):** Normalizes coverage to a 1–5 scale where score 1 exposes single-engine dependencies as high-priority blind spots, while score 5 rewards defense-in-depth redundancy.

---

## 2. Operational Ownership & Git Lifecycle Provenance

Graft separates operational accountability (`metadata.owners` in the rule YAML) from historical revision provenance extracted from Git in a single pass (`git log --follow --format=%aI%x00%aN%x00%aE`) via Python's standard library `subprocess`:

- **Initial Committer (`author`):** Author name (`%aN`) of the earliest commit in the file's history across renames.
- **Accountable Owners (`owners` & `owner_count`):** Sourced directly from `metadata.owners` in the rule envelope to identify the teams or individuals responsible for maintaining the rule today, paired with `owner_count` (`len(metadata.owners)`) to surface single-owner bus-factor risk.
- **Creation Date (`created_at`):** Earliest commit timestamp across file history, normalized to UTC `YYYY-MM-DD` for native date parsing in Polars and Google Sheets.
- **Last Modified Date (`last_modified_at`):** Most recent commit timestamp across file history, normalized to UTC `YYYY-MM-DD`.
- **Commit Revision Count (`review_count`):** Total number of commits touching the file across renames (`--follow`).
- **Contributor Breadth (`contributor_count`):** Count of distinct, case-insensitively normalized Git author emails (`%aE`) touching the file. Credit external research authors in `metadata.references`.
- **Offline / Untracked Fallback:** Automatically falls back to `"Unknown"` strings and `0` counts if files are uncommitted or executed in environments lacking Git history (e.g. container builds).

---

## 3. Rule Catalog Generation

Export comprehensive detection catalogs enriched with deployment status, MITRE ATT&CK associations, accountable rule owners, and Git lifecycle metrics across multiple formats.

### Terminal Table (`--format=table`, Default)
Fast, on-screen inspection without piping to files:

```bash
graft export catalog
```

### Markdown Catalog (`--format=markdown`)
Ideal for automated documentation generation and repository wiki tracking:

```bash
graft export catalog --format=markdown --out docs/RULE_CATALOG.md
```

| Rule Name | Engine | Type | Status | MITRE ATT&CK | Author | Owners | Owner Count | Created | Last Updated | Reviews | Contributors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gcp_iam_service_account_key_create` | secops | custom | enabled | TA0003:T1098.001, TA0004:T1098.001 | Joe Lopes | Cloud Security Operations | 1 | 2026-09-17 | 2026-09-29 | 12 | 1 |
| `gcp_storage_iam_public_access_granted` | secops | custom | enabled | TA0001:T1078.004, TA0112:T1685 | Joe Lopes | Cloud Security Operations | 1 | 2026-09-17 | 2026-09-29 | 10 | 1 |
| `workspace_nrd_possible_phishing` | secops | custom | enabled | TA0001:T1566.002 | Joe Lopes | Joe Lopes <lopes.id> | 1 | 2026-09-17 | 2026-09-29 | 8 | 1 |
| `gcti_active_breach_network_indicators` | secops | managed | silent | TA0011:T1071.001 | Joe Lopes | Cloud Security Operations | 1 | 2026-09-30 | 2026-09-30 | 1 | 1 |

### CSV Catalog (`--format=csv`)
Generate spreadsheet-ready exports for Polars, Google Sheets, security audits, and reporting pipelines:

```bash
graft export catalog --format=csv --out exports/detection_catalog.csv
```

CSV exports contain 15 normalized fields:
`id, name, engine, rule_type, status, description, mitre_attack, tags, author, owners, owner_count, created_at, last_modified_at, review_count, contributor_count`.

### JSON Catalog (`--format=json`)
Structured JSON for feeding security data lakes, BigQuery, or internal developer portals:

```bash
graft export catalog --format=json
```


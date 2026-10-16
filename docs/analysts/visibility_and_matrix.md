# Visibility, Threat Matrix & Catalog Tooling

Graft turns detection repositories into high-visibility threat intelligence and coverage assets. Detection engineers, CTI analysts, SOC managers, and compliance auditors can inspect MITRE ATT&CK enrichments, compute 3-state coverage gaps, export ATT&CK Navigator heatmaps, and generate Git-attributed rule catalogs directly from the command line—100% offline.

---

## 1. Two-Tier Pre-Compiled MITRE ATT&CK Storage & Version Management

Graft ships with pre-compiled MITRE ATT&CK Enterprise STIX data in `src/graft/data/` (currently pinned to **v20.0**) so users and CI/CD pipelines never have to download raw 40 MB STIX bundles during onboarding or routine runs.

To keep daily operations (`graft lint`, `graft mitre coverage`, `graft export`) sub-second while still providing deep detection blueprints on demand, Graft splits the taxonomy into two files:
- **`src/graft/data/mitre_attack.json` (~570 KB):** Core techniques, sub-techniques, tactics, platforms, revocation/deprecation pointers (`revoked_by`, `status`), Detection Strategy summaries (`DETxxxx`), Data Components (`DCxxxx`), Threat Groups (`Gxxxx`), and Mitigations (`Mxxxx`). Loaded by `graft lint`, `graft mitre coverage`, `graft mitre gaps`, and `graft export`.
- **`src/graft/data/mitre_analytics.json` (~2.2 MB):** Full platform-specific behavioral analytics (`ANxxxx`), log source channel mappings (`log_sources`), and tunable parameters (`mutable_elements`). Lazy-loaded **only** when `graft mitre inspect` is invoked with `--analytics`, `--full`, or a `DETxxxx`/`ANxxxx` ID.

> [!TIP]
> **Bumping MITRE ATT&CK Versions (`graft mitre update`):**
> Graft never hardcodes the MITRE version in application logic—every validator, report header, and Navigator layer reads `version` dynamically from `src/graft/data/mitre_attack.json`.
> - **Check for upstream releases (fast, 33 KB index lookup):**
>   ```bash
>   uv run graft mitre update --check
>   ```
>   *(Also runs non-blockingly in `.githooks/pre-commit` and CI so maintainers are notified when MITRE publishes a new version).*
> - **Upgrade to the latest upstream Enterprise ATT&CK release (or a specific version):**
>   ```bash
>   uv run graft mitre update
>   # or pin a specific version / custom STIX bundle URL:
>   uv run graft mitre update --version 20.0
>   ```
>   Running `graft mitre update` recompiles both `mitre_attack.json` and `mitre_analytics.json` deterministically so you can immediately run `uv run graft lint` to see if any mapped techniques were newly revoked or deprecated.

---

## 2. MITRE ATT&CK Intelligence & CTI Analysis (`graft mitre`)

While `graft export` generates portable artifacts for external tools, `graft mitre` is the interactive CLI workspace for detection engineers, CTI analysts, and AI skills (`/cti-coverage`, `/scaffold-rule`, `/review-rule`).

```mermaid
flowchart LR
    STIX["<b>Two-Tier STIX Store</b><br/>• mitre_attack.json (570 KB)<br/>• mitre_analytics.json (2.2 MB)"] --> ENGINE["<b>MITRE Intelligence Service</b><br/><code>src/graft/core/mitre_intelligence.py</code>"]
    RULES["<b>Rule Repository</b><br/>• Custom Rules (custom/*.yaml)<br/>• Registered Managed Rules"] --> ENGINE
    ENGINE --> COV["<code>graft mitre coverage</code><br/>Covered techniques &amp; enrichments"]
    ENGINE --> GAPS["<code>graft mitre gaps</code><br/>3-state roll-up ranked by Gxxxx"]
    ENGINE --> INSP["<code>graft mitre inspect</code><br/>Targeted T / DET / AN / DC / G / M lookup"]
```

### 1. Coverage Summary & Enrichments (`graft mitre coverage`)
Inspect covered techniques across all engines (or filtered by `--engine`, `--platform`, `--group`, or `--data-component`). Pass `--enrich` to surface associated Threat Groups (`Gxxxx`), Detection Strategies (`DETxxxx`), Data Components (`DCxxxx`), and Mitigations (`Mxxxx`):

```bash
# Default coverage table
uv run graft mitre coverage

# Enriched coverage table filtered to IaaS techniques
uv run graft mitre coverage --platform IaaS --enrich

# Machine-readable JSON or CSV for CTI skills and pipelines
uv run graft --json mitre coverage --enrich
uv run graft mitre coverage --format csv --enrich --out exports/mitre_coverage.csv
```

**Example Output (`graft mitre coverage --enrich`):**
```text
MITRE ATT&CK v20.0 Coverage (Total Rules: 6 | Covered Techniques: 8)
======================================================================================================================
Technique ID  Technique Name             Rules Groups Strategies   Data Components    Rules / Detections
----------------------------------------------------------------------------------------------------------------------
T1018         Remote System Discovery    1     43     DET0574      DC0032,DC0055      multiple_hosts_scanned
T1046         Network Service Discovery  1     33     DET0376      DC0032,DC0078      multiple_ports_scanned
T1071.001     Web Protocols              1     58     DET0027      DC0032,DC0064      gcti_breach_network_indic...
T1078.004     Cloud Accounts             1     14     DET0546      DC0002,DC0067      gcp_storage_bucket_public...
T1098.001     Additional Cloud Credent.. 1     1      DET0531      DC0010,DC0066      gcp_service_account_key_c...
T1566.002     Spearphishing Link         1     48     DET0107      DC0032,DC0038      workspace_nrd_email_opened
T1595.001     Scanning IP Blocks         2     2      DET0817      DC0078,DC0085      multiple_hosts_scanned, m...
T1685         Disable or Modify Tools    1     33     DET0497      DC0018,DC0032      gcp_storage_bucket_public...
```

### 2. Three-State Gap Analysis (`graft mitre gaps`)
Compute prioritized detection gaps across the MITRE ATT&CK matrix using a **3-state parent/sub-technique roll-up** (`covered`, `partial`, `uncovered`) ranked by Threat Group (`Gxxxx`) prevalence:
- **`covered`**: The technique (or every in-scope sub-technique under a parent) has at least one active rule.
- **`partial`**: Only the parent technique is mapped without specific sub-techniques, or only a subset of in-scope sub-techniques are covered (e.g., covering `T1078.004` Cloud Accounts while leaving sibling `T1078` sub-techniques uncovered).
- **`uncovered`**: Zero rules cover the parent technique or any of its sub-techniques.

```bash
# Top 10 uncovered/partial gaps on IaaS ranked by Threat Group prevalence
uv run graft mitre gaps --platform IaaS --top 10

# Gaps for a specific Threat Group (by G-ID or alias/name)
uv run graft mitre gaps --group APT29 --platform IaaS

# "Quick-win" gaps that rely on a Data Component (DCxxxx) your SIEM already ingests
uv run graft mitre gaps --data-component DC0010 --top 10
```

**Example Output (`graft mitre gaps --platform IaaS --top 5`):**
```text
MITRE ATT&CK v20.0 Gap Analysis [platform=IaaS]
In Scope: 104 | Covered: 4 | Partial: 3 | Uncovered: 97 (Showing 5 gaps)
================================================================================================================
Technique ID  State      Groups  Technique Name                 Strategies   Data Components
----------------------------------------------------------------------------------------------------------------
T1082         uncovered  59      System Information Discovery   DET0525      DC0032, DC0063, DC0064
T1078         partial    49      Valid Accounts                 DET0560      DC0002, DC0032, DC0067
T1190         uncovered  47      Exploit Public-Facing Applic.. DET0080      DC0016, DC0032, DC0038
T1049         uncovered  33      System Network Connections D.. DET0320      DC0021, DC0032, DC0064
T1518.001     uncovered  27      Security Software Discovery    DET0016      DC0016, DC0032, DC0064
```

### 3. Targeted Entity & Analytic Inspection (`graft mitre inspect`)
Query specific MITRE entities (`Txxxx[.xxx]`, `TAxxxx`, `DETxxxx`, `ANxxxx`, `DCxxxx`, `Gxxxx`, `Mxxxx`, or Threat Group name/alias) without loading full STIX files. Pass `--analytics` (or `--full`) to lazy-load platform-specific `ANxxxx` analytics, `log_sources`, and tunable `mutable_elements`:

```bash
# Inspect a technique with its IaaS analytics, log sources, and tunable parameters
uv run graft mitre inspect T1098.001 --analytics --platform IaaS

# Inspect a Detection Strategy, Analytic, Threat Group, or Data Component directly
uv run graft mitre inspect DET0531 AN1470 G0016 DC0010

# Structured JSON output for AI skills (/cti-coverage, /scaffold-rule, /review-rule)
uv run graft --json mitre inspect T1098.001 --analytics --platform IaaS
```

---

## 3. MITRE ATT&CK Navigator Layer Export (`graft export navigator`)

Generate JSON layers adhering to the MITRE ATT&CK Navigator v4.5 specification (`graft export navigator`, with `graft export matrix` and `graft export mitre` supported as aliases):

```bash
# Export unified Navigator JSON layer (default format for 'export navigator' is navigator JSON)
uv run graft export navigator --out exports/graft_coverage.json

# Export engine-scoped layer with custom gradient color
uv run graft export navigator --engine secops --color "#4285F4" --out exports/secops_coverage.json

# Export filtered Navigator layer with STIX enrichments and uncovered gaps highlighted in red (#ea4335, score 0)
uv run graft export navigator --platform IaaS --enrich --include-gaps --out exports/iaas_posture.json

# Backward-compatible matrix alias (supports --format table | navigator)
uv run graft export matrix --format table --engine secops
```

Import the generated JSON file directly into the [MITRE ATT&CK Navigator Web App](https://mitre-attack.github.io/attack-navigator/) to visualize detection coverage heatmaps, inspect rule metadata and `DETxxxx`/`DCxxxx`/`Gxxxx` enrichments (`--enrich`), and highlight uncovered blind spots (`--include-gaps`).

### Multi-Engine Gap Analysis in MITRE Navigator
Operators managing hybrid detection platforms (e.g. Google SecOps and endpoint security) can export distinct layers per engine using `--engine <name>` and `--color <hex>`, then leverage Navigator's layer combination arithmetic for automated gap analysis.

For an in-depth breakdown of Navigator layer expressions and visual gap analysis, see:
👉 **[Gap Analysis with MITRE Navigator](https://lopes.id/log/gap-analysis-mitre-navigator/)**

Each technique in the exported layer is scoped strictly to its tactic shortname (e.g. `initial-access`, `defense-impairment`) with `selectTechniquesAcrossTactics: false`, ensuring scores remain locked to their appropriate tactic column. Combining layers using Navigator's **Create Layer from Other Layers** feature enables:
- **Redundancy Evaluation (`min(a, b)`):** Highlights techniques defended by multiple engines simultaneously.
- **Combined Coverage (`max(a, b)`):** Surfaces the complete detection footprint.
- **Normalized Gap Analysis (`1 + 4 * (1 - (max(a, b) * (1 - min(a, b))))`):** Normalizes coverage to a 1–5 scale where score 1 exposes single-engine dependencies as high-priority blind spots, while score 5 rewards defense-in-depth redundancy.

---

## 4. Operational Ownership & Git Lifecycle Provenance

Graft separates operational accountability (`metadata.owners` in the rule YAML) from historical revision provenance extracted from Git in a single pass (`git log --follow --format=%aI%x00%aN%x00%aE`) via Python's standard library `subprocess`:

- **Initial Committer (`author`):** Author name (`%aN`) of the earliest commit in the file's history across renames.
- **Accountable Owners (`owners` & `owner_count`):** Sourced directly from `metadata.owners` in the rule envelope to identify the teams or individuals responsible for maintaining the rule today, paired with `owner_count` (`len(metadata.owners)`) to surface single-owner bus-factor risk.
- **Creation Date (`created_at`):** Earliest commit timestamp across file history, normalized to UTC `YYYY-MM-DD` for native date parsing in Polars and Google Sheets.
- **Last Modified Date (`last_modified_at`):** Most recent commit timestamp across file history, normalized to UTC `YYYY-MM-DD`.
- **Commit Revision Count (`review_count`):** Total number of commits touching the file across renames (`--follow`).
- **Contributor Breadth (`contributor_count`):** Count of distinct, case-insensitively normalized Git author emails (`%aE`) touching the file. Credit external research authors in `metadata.references`.
- **Offline / Untracked Fallback:** Automatically falls back to `"Unknown"` strings and `0` counts if files are uncommitted or executed in environments lacking Git history (e.g. container builds).

---

## 5. Rule Catalog Generation (`graft export catalog`)

Export comprehensive detection catalogs enriched with deployment status, MITRE ATT&CK associations, accountable rule owners, and Git lifecycle metrics across multiple formats (`table`, `markdown`, `csv`, `json`). Pass `--enrich` to append MITRE `platforms`, `detection_strategies`, `data_components`, `groups`, and `mitigations` to each rule entry.

### Terminal Table (`--format=table`, Default)
Fast, on-screen inspection without piping to files:

```bash
uv run graft export catalog
# or with MITRE STIX enrichments:
uv run graft export catalog --enrich
```

### Markdown Catalog (`--format=markdown`)
Ideal for automated documentation generation and repository wiki tracking:

```bash
uv run graft export catalog --format=markdown --out docs/RULE_CATALOG.md
```

| Rule Name | Engine | Type | Status | MITRE ATT&CK | Author | Owners | Owner Count | Created | Last Updated | Reviews | Contributors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gcp_service_account_key_created` | secops | custom | enabled | TA0003:T1098.001, TA0004:T1098.001 | Joe Lopes | Joe Lopes | 1 | 2026-09-17 | 2026-10-01 | 13 | 1 |
| `gcp_storage_bucket_public_access_granted` | secops | custom | enabled | TA0001:T1078.004, TA0112:T1685 | Joe Lopes | Joe Lopes | 1 | 2026-09-17 | 2026-10-01 | 11 | 1 |
| `workspace_nrd_email_opened` | secops | custom | enabled | TA0001:T1566.002 | Joe Lopes | Joe Lopes | 1 | 2026-09-17 | 2026-10-01 | 9 | 1 |
| `gcti_breach_network_indicator_matched` | secops | managed | silent | TA0011:T1071.001 | Joe Lopes | Joe Lopes | 1 | 2026-09-30 | 2026-10-01 | 2 | 1 |

### CSV Catalog (`--format=csv`)
Generate spreadsheet-ready exports for Polars, Google Sheets, security audits, and reporting pipelines:

```bash
uv run graft export catalog --format=csv --out exports/detection_catalog.csv
```

By default, CSV exports contain 15 normalized fields:
`id, name, engine, rule_type, status, description, mitre_attack, tags, author, owners, owner_count, created_at, last_modified_at, review_count, contributor_count` (plus `mitre_platforms, mitre_strategies, mitre_data_components, mitre_groups, mitre_mitigations` when `--enrich` is passed).

### JSON Catalog (`--format=json`)
Structured JSON for feeding security data lakes, BigQuery, or internal developer portals:

```bash
uv run graft export catalog --format=json
uv run graft export catalog --format=json --enrich
```

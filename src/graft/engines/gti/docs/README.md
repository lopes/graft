# Google Threat Intelligence (`gti`) Engine Setup & Operations Guide

The `gti` adapter connects Graft to the **Google Threat Intelligence (VirusTotal v3)** REST API (`https://www.virustotal.com/api/v3`), bringing native YARA-X **Livehunt** rulesets (`/api/v3/intelligence/hunting_rulesets`) and **Retrohunt** historical corpus jobs (`/api/v3/intelligence/retrohunt_jobs`) into peer-reviewed GitOps workflows and unified MITRE ATT&CK coverage matrices.

---

## 1. What Graft Commands & Deploys in GTI

```mermaid
flowchart TD
    RULE["Graft GTI Rule Envelope<br/>(rulesets/gti/custom/*.yaml)"]
    COMPILER["GTICompilerAdapter<br/>• Partition imports &amp; body<br/>• Inject YARA meta: attribution"]

    RULE --> COMPILER

    COMPILER --> DEP_TYPE{"deployment.type<br/>(required)"}
    DEP_TYPE -- "livehunt" --> LH["GTI Livehunt API<br/>POST / PATCH / DELETE<br/>/api/v3/intelligence/hunting_rulesets<br/>subtype (required): file | url | domain | ip_address"]
    DEP_TYPE -- "retrohunt (enabled: true)" --> RH["GTI Retrohunt API<br/>POST / GET<br/>/api/v3/intelligence/retrohunt_jobs<br/>corpus: main | goodware"]
```

| Artifact / Capability | Supported in `gti`? | How Graft Handles It |
| :--- | :---: | :--- |
| **Livehunt Rulesets** (`deployment.type: "livehunt"`) | **Yes** (`custom_rules: true`) | Synchronized via `graft gti diff`, `apply`, and `pull` against `/api/v3/intelligence/hunting_rulesets`. Continuously evaluates incoming GTI submissions in real time across 4 explicit entity subtypes (`deployment.subtype`: `"file"`, `"url"`, `"domain"`, `"ip_address"`). Syncs `metadata.tags` 1-to-1 with GTI's `attributes.tags`. |
| **Retrohunt Jobs** (`deployment.type: "retrohunt"`) | **Yes** (`custom_rules: true`, `replay_testing: true`) | Configured declaratively under `deployment` (`type: "retrohunt"`, `corpus: "main" \| "goodware"`, optional `start_time`, `end_time`). Kept dormant in Git while `enabled: false` (still linted, syntax-verified, unit-tested, and cataloged) and submitted to `/api/v3/intelligence/retrohunt_jobs` when `enabled: true` is applied. Updating or disabling a Retrohunt rule in Git never deletes or aborts running tasks or historical scan results. Also runnable on-demand via `graft gti test`. |
| **Reusable String Datasets** (`datasets/<name>.yaml`) | **No** (`datasets: false`) | GTI's YARA-X engine does not provide a server-side lookup table or reference list resource (`DatasetPort` is disabled). GTI rules use 100% native YARA-X without Graft preprocessor hacks; `graft lint` rejects `%<dataset>` tokens in `rulesets/gti/`. |
| **Vendor-Managed Rules** (`rulesets/gti/managed/`) | **No** (`managed_rules: false`) | GTI does not expose vendor-managed curated rulesets on `/intelligence/hunting_rulesets` (`ManagedEnginePort` is disabled). All rulesets visible in a shared GTI organization are user-created (`owner.type == "user"`). |

---

## 2. Environment Configuration, Least-Privilege Account & GTI Permissions

Copy [`.env.example`](../.env.example) to `src/graft/engines/gti/.env` (automatically loaded by Graft at startup and excluded from Git via `.gitignore`):

```bash
export GRAFT_GTI_API_KEY="your-dedicated-graft-user-gti-api-key"
# Optional discovery scope: "owner:self" (default), "tag:<tag>", or "all"
export GRAFT_GTI_FILTER="owner:self"
# Optional default notification recipients for Livehunt / Retrohunt matches
export GRAFT_GTI_NOTIFICATION_EMAILS="soc-alerts@example.com"
```

### GTI Permissions & Least-Privilege Crash Course (Dedicated Non-Admin User Account)
Unlike Google SecOps (which authenticates via a GCP IAM Service Account), every Google Threat Intelligence API key (`x-apikey`) belongs to a specific **GTI User Account** inside an Organization / Group. In a shared GTI Group, all members can view Livehunt rulesets created by colleagues, while Retrohunt jobs are strictly scoped to the user account that submitted them (`/api/v3/users/{user_id}/retrohunt_jobs`). Additionally, GTI allows individual rule owners to grant **Group Edit** access (`relationships.editors` on a Livehunt ruleset), which makes a colleague's ruleset editable by every member of the Group—and causes GTI's `GET /api/v3/users/{user_id}/hunting_rulesets` endpoint to return both `{user_id}`'s own rulesets and any group-editable colleague rulesets. For production GitOps, **provision a dedicated GTI user account exclusively for Graft** (for example, `graft-automation@example.com`) within your GTI Group and use its API key in CI/CD so human analysts' personal rulesets and Retrohunt jobs never collide with Graft's state.

> [!CAUTION]
> **Never grant Group Administrator privileges to the Graft GTI user account.** A GTI Group Administrator can modify or delete any member's Livehunt rulesets across the entire organization and carries broad administrative privileges that violate least privilege if the API key is ever exposed. Running Graft as a standard (non-admin) dedicated Group member provides two defense-in-depth guarantees: (1) [`GTIDeployerAdapter`](../deployer.py) defaults to `GRAFT_GTI_FILTER="owner:self"`, requests `relationships=owner`, and explicitly filters out any ruleset where `relationships.owner.data.id != current_user_id` (even if a colleague enabled Group Edit access on their rule), plus enforces a hard `403 OwnershipGuardError` before any `PATCH` or `DELETE`; and (2) the GTI API itself blocks a non-admin account from mutating non-shared colleague rulesets. The only limitation of a dedicated non-admin account is that it cannot directly take over or overwrite an existing brownfield ruleset owned by a colleague unless that colleague either enables Group Edit / transfers ownership or you import the rule into Git (`GRAFT_GTI_FILTER="all" uv run graft gti pull`), deploy it under the dedicated Graft account, and retire the legacy copy.

### 1-to-1 `metadata.tags` Synchronization
Graft does **not** inject a hidden `"graft"` tag into your GTI rulesets. Because ownership isolation is handled cleanly by the dedicated Graft user account (`GRAFT_GTI_FILTER="owner:self"`), `metadata.tags` in your rule YAML is synchronized **1-to-1** with GTI's Livehunt `attributes.tags` (and embedded as `tags = "..."` in YARA `meta:` for lossless round-tripping across both Livehunt and Retrohunt):
- All tags across Graft (`metadata.tags` in custom rules, managed rules, and datasets) must match `^[a-z0-9_/:-]{1,32}$` (lowercase letters, digits, hyphens `-`, underscores `_`, colons `:`, and forward slashes `/`, up to 32 characters per tag).
- Avoid repeating attributes already captured in dedicated envelope fields (`engine`, `deployment.type`, `deployment.subtype`, or `metadata.mitre` tactics). Use `metadata.tags` for organizational, domain, threat-family, or telemetry grouping (e.g., `["web", "sso", "phishing"]` or `["windows", "pe", "lsass"]`).

---

## 3. Configuring `deployment`: Livehunt vs. Retrohunt

In Graft, [`BaseDeploymentConfig`](../../../core/models/rule.py) in Core is completely empty—every engine defines and validates its own `deployment` block via [`schemas/custom.schema.json`](../schemas/custom.schema.json).

The `gti` schema requires `deployment.type` (`"livehunt"` or `"retrohunt"`) and `deployment.enabled` (`boolean`) on every rule—with zero implicit defaults or stream guessing:

### Mode A: Livehunt Deployment (`type: "livehunt"`)
Evaluates newly submitted files, URLs, domains, or IP addresses in real time:

```yaml
deployment:
  type: "livehunt"
  subtype: "url"
  enabled: true
  daily_limit: 100
  notification_emails:
    - "soc-alerts@example.com"
```

| Field | Type & Constraints | Description |
| :--- | :--- | :--- |
| `type` | `"livehunt"` (**required**) | Selects GTI Livehunt (`/api/v3/intelligence/hunting_rulesets`). |
| `subtype` | `"file" \| "url" \| "domain" \| "ip_address"` (**required**) | Entity stream evaluated by Livehunt (`attributes.match_object_type` in GTI JSON:API). Must be declared explicitly—Graft never guesses `subtype` from `vt.net.*` identifiers. |
| `enabled` | `boolean` (**required**) | Whether the Livehunt ruleset is actively evaluating incoming GTI submissions. |
| `daily_limit` | `integer` (`1..10000`, optional, default `100`) | Maximum match notifications per 24-hour window (`attributes.limit` in GTI JSON:API). |
| `notification_emails` | `array[string]` (optional) | Email addresses notified when Livehunt records a match. Falls back to `GRAFT_GTI_NOTIFICATION_EMAILS`. |

> [!NOTE]
> Livehunt rules cannot declare Retrohunt-only fields (`corpus`, `start_time`, `end_time`); `graft lint` rejects mixed configurations offline.

### Mode B: Retrohunt Deployment (`type: "retrohunt"`)
Scans GTI's historical file corpus (`"main"` or `"goodware"`) over an optional UTC time window:

```yaml
deployment:
  type: "retrohunt"
  enabled: false
  corpus: "main"
  start_time: "2026-01-01T00:00:00Z"
  end_time: "2026-03-31T23:59:59Z"
  notification_emails:
    - "threat-hunting@example.com"
```

| Field | Type & Constraints | Description |
| :--- | :--- | :--- |
| `type` | `"retrohunt"` (**required**) | Selects GTI Retrohunt (`/api/v3/intelligence/retrohunt_jobs`). |
| `corpus` | `"main" \| "goodware"` (**required**) | `"main"` scans GTI's historical file submissions (~3–12 months); `"goodware"` scans ~1M NSRL known-good files for false-positive benchmarking. |
| `enabled` | `boolean` (**required**) | Controls job submission. When `false`, the rule remains dormant in Git (linted, syntax-verified, unit-tested, and cataloged without consuming Retrohunt job quota). Setting `enabled: true` and running `graft gti apply` submits the batch scan job to GTI. Setting `enabled: false` after a job runs disables future schedule submissions while **preserving all running tasks and historical scan results** in GTI. |
| `start_time` | ISO-8601 UTC string (optional) | Lower bound for file submission timestamp (`YYYY-MM-DDTHH:MM:SSZ`), converted to Unix epoch seconds in GTI's `attributes.time_range.start`. |
| `end_time` | ISO-8601 UTC string (optional, requires `start_time`) | Upper bound for file submission timestamp (`YYYY-MM-DDTHH:MM:SSZ`), converted to Unix epoch seconds in GTI's `attributes.time_range.end`. |
| `notification_emails` | `array[string]` (optional) | Email addresses notified when the Retrohunt job finishes (`attributes.notification_email`). |

> [!NOTE]
> Retrohunt rules always scan historical files and cannot declare Livehunt-only fields (`subtype`, `daily_limit`).

---

## 4. Authoring Native YARA-X `logic`

### 1. `$LOGIC_IMPORTS` + `$LOGIC_BODY` Separation
Analysts write only top-level `import "<module>"` statements (`import "vt"`, `import "pe"`, `import "elf"`, `import "math"`, etc.) followed by `strings:` (optional) and `condition:` in `logic`—never a `rule <name> { meta: ... }` wrapper:

```yaml
logic: |
  import "vt"

  condition:
    vt.net.url.new_url and
    not (
      vt.net.domain.root == "example.com" or
      vt.net.domain.root == "example.org"
    ) and
    (
      vt.net.url.raw icontains "login" or
      vt.net.url.raw icontains "signin"
    )
```

### 2. Native YARA-X Synthesis (`graft gti render`)
Running `uv run graft gti render` partitions top-level `import "..."` lines above the `rule <rule_name> { ... }` declaration and injects Graft's attribution and MITRE ATT&CK tags into the YARA `meta:` section:

```yara
import "vt"

rule sso_login_portal_impersonated {
  meta:
    graft_id = "8f14e45f-ceea-467a-a124-000000000001"
    description = "Detects newly observed URLs impersonating corporate SSO login portals outside sanctioned root domains"
    owners = "Threat Intelligence, Detection Engineering"
    mitre_tactic = "initial-access"
    mitre_technique = "T1566.002"
    tags = "web, sso, phishing"

  condition:
    vt.net.url.new_url and
    not (
      vt.net.domain.root == "example.com" or
      vt.net.domain.root == "example.org"
    ) and
    (
      vt.net.url.raw icontains "login" or
      vt.net.url.raw icontains "signin"
    )
}
```

---

## 5. Verification & Replay Testing (`graft gti verify` & `graft gti test`)

### 1. Server-Side YARA-X Verification (`graft gti verify`)
GTI does not expose a dedicated stateless syntax-check endpoint. When `uv run graft --json gti verify` runs:
1. Graft performs an instant local structural check (non-empty `condition:`, balanced `{}` and `()`).
2. If `GRAFT_GTI_API_KEY` is configured, [`GTICompilerAdapter`](../compiler.py) submits a transient **disabled** ruleset (`POST /api/v3/intelligence/hunting_rulesets` with `enabled: false`, explicit `match_object_type`, and name `__graft_verify_<uuid8>__`) to invoke GTI's real server-side YARA-X compiler.
3. A `finally:` block immediately executes `DELETE /api/v3/intelligence/hunting_rulesets/{id}`, guaranteeing zero leftover probe rulesets or live alerts. Any remote compiler line number is adjusted back to the local YAML `logic` line offset.

### 2. Dual-Mode Replay Testing (`graft gti test`)
[`GTIReplayAdapter`](../replay.py) supports two test vector modes in the `tests:` block:

#### Mode 1: Offline Synthetic Unit Tests (Default — Fast, Deterministic, Zero Quota)
Evaluates `vt.net.*`, `vt.metadata.*`, `filesize`, and `strings:` (`sample_text`) in memory against synthetic event payloads:

```yaml
tests:
  - id: "match_unlisted_sso_phishing_url"
    description: "Newly observed URL containing SSO login paths on an external domain triggers a match"
    expect: 1
    events:
      - timestamp: "2026-10-15T12:00:00Z"
        payload:
          vt.net.url.new_url: true
          vt.net.domain.root: "login-verify-portal.test"
          vt.net.url.raw: "https://login-verify-portal.test/sso/login?client_id=corp"
          vt.net.url.downloaded_file.analysis_stats.malicious: 3
```

For file/Retrohunt rules with a `strings:` section and `filesize`, pass `sample_text` and `filesize` in `payload`:

```yaml
tests:
  - id: "match_lsass_minidump_pe_strings"
    description: "PE executable containing MiniDumpWriteDump, lsass.exe, and SeDebugPrivilege matches"
    expect: 1
    events:
      - timestamp: "2026-10-15T12:00:00Z"
        payload:
          vt.metadata.file_type: "vt.FileType.PE_EXE"
          filesize: 204800
          sample_text: "MiniDumpWriteDump dbghelp.dll lsass.exe SeDebugPrivilege"
```

#### Mode 2: On-Demand Live Retrohunt Corpus Tests (`mode: "retrohunt"`)
To test a rule against GTI's live historical file corpus (`"main"` or `"goodware"`) during `graft gti test`, set `mode: "retrohunt"` in the event `payload`:

```yaml
tests:
  - id: "goodware_corpus_zero_false_positives"
    description: "Verify zero false positives against GTI goodware corpus window"
    expect: 0
    events:
      - timestamp: "2026-10-15T12:00:00Z"
        payload:
          mode: "retrohunt"
          corpus: "goodware"
          time_range:
            start: 1767225600
            end: 1769904000
```

Graft submits `POST /api/v3/intelligence/retrohunt_jobs`, polls `GET /api/v3/intelligence/retrohunt_jobs/{id}` until `status` reaches `"finished"` or `"aborted"`, asserts `num_matches == expect`, and deletes the transient Retrohunt job in a `finally:` block.

---

## 6. Local Workstation vs. GitHub Actions CI/CD Configuration

Graft follows a simple two-tier credential model for GTI: **a local git-ignored `.env` file for workstation development** and **a GitHub Actions Repository Secret (`GRAFT_GTI_API_KEY`) for automated CI/CD**.

### 1. Provision the GTI Automation Account & Copy Its API Key
1. In your Google Threat Intelligence Organization / Group, create a dedicated **standard (non-admin) GTI User Account** for Graft (e.g., `graft-automation@example.com`). In a single-user lab or evaluation tenant where creating a second account is not possible, use your non-admin user account with `GRAFT_GTI_FILTER="owner:self"` (the default).
2. Log in as that GTI account, open your user profile menu $\rightarrow$ **API Key**, and copy the 64-character hexadecimal API key.

### 2. Local Workstation Configuration (`src/graft/engines/gti/.env`)
For local CLI commands (`graft gti verify`, `graft gti test`, `graft gti diff`, `graft gti apply`, `graft gti pull`), store your key in `src/graft/engines/gti/.env` (automatically loaded by Graft and ignored by Git):

```bash
cp src/graft/engines/gti/.env.example src/graft/engines/gti/.env
```

Edit `src/graft/engines/gti/.env`:

```bash
GRAFT_GTI_API_KEY="your-64-char-gti-api-key"
GRAFT_GTI_FILTER="owner:self"
# Optional: comma-separated recipients for Livehunt / Retrohunt match notifications
# GRAFT_GTI_NOTIFICATION_EMAILS="soc-alerts@example.com"
```

### 3. GitHub Actions CI/CD Configuration (`.github/workflows/`)
Graft's [`.github/workflows/pr-validation.yml`](../../../../../.github/workflows/pr-validation.yml) (`gti-cloud-gates`) and [`.github/workflows/deploy-production.yml`](../../../../../.github/workflows/deploy-production.yml) automatically activate live GTI server-side YARA-X compilation (`graft gti verify`), replay testing (`graft gti test`), PR reconciliation plans (`graft gti diff`), and mainline synchronization (`graft gti apply --env production --all`) as soon as `GRAFT_GTI_API_KEY` is added to your repository secrets:

```bash
# 1. Required: Store the GTI API key as an encrypted GitHub Actions Repository Secret
gh secret set GRAFT_GTI_API_KEY --repo <owner>/<repo>

# 2. Optional: Set discovery filter (defaults to "owner:self" if omitted)
gh variable set GRAFT_GTI_FILTER --body "owner:self" --repo <owner>/<repo>

# 3. Optional: Set default notification emails for Livehunt/Retrohunt alerts
gh variable set GRAFT_GTI_NOTIFICATION_EMAILS --body "soc-alerts@example.com" --repo <owner>/<repo>
```

| GitHub Setting | Type | Name | Required? | Purpose |
| :--- | :---: | :--- | :---: | :--- |
| **Secrets** (`Settings -> Secrets and variables -> Actions -> Secrets`) | `Secret` | `GRAFT_GTI_API_KEY` | **Yes** (for cloud gates) | Authenticates `gti-cloud-gates` on PRs (`verify`, `test`, `diff`) and `deploy-production` on `main` (`apply --all`). If unset, CI still runs offline schema linting and Mode 1 synthetic YARA-X unit tests (`graft gti test`) while skipping live GTI API steps. |
| **Variables** (`Settings -> Secrets and variables -> Actions -> Variables`) | `Variable` | `GRAFT_GTI_FILTER` | Optional | Remote ruleset discovery scope (`owner:self` default, `tag:<tag>`, or `all`). |
| **Variables** (`Settings -> Secrets and variables -> Actions -> Variables`) | `Variable` | `GRAFT_GTI_NOTIFICATION_EMAILS` | Optional | Default comma-separated email recipients when a rule omits `deployment.notification_emails`. |

---

## 7. CLI Operations Reference

```bash
# 1. Scaffold a new GTI custom rule
uv run graft gti new brand_sso_portal_impersonated

# 2. Validate YAML schemas, deployment type/subtype constraints, and MITRE mappings offline
uv run graft --json lint rulesets/gti/

# 3. Render synthesized YARA-X rule offline (with meta: attribution)
uv run graft --json gti render --all

# 4. Verify YARA-X syntax against GTI's server-side compiler
uv run graft --json gti verify --all

# 5. Execute unit test vectors (and any retrohunt test vectors)
uv run graft --json gti test

# 6. Diff and apply Livehunt rulesets and enabled Retrohunt jobs (scoped to owner:self)
uv run graft --json gti diff --all
uv run graft --json gti apply --all

# 7. Pull existing Livehunt rulesets & Retrohunt jobs owned by the Graft user into 5-block YAML envelopes
uv run graft --json gti pull
```

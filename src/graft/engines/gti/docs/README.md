# Google Threat Intelligence (`gti`) Engine Setup & Operations Guide

This guide is a practitioner runbook to prepare **Google Threat Intelligence (VirusTotal Enterprise v3)** (`https://www.virustotal.com/api/v3`) for Graft. Follow these instructions to understand how GTI works inside Graft, provision a dedicated least-privilege GTI automation account, verify permissions and server-side YARA-X compilation with a pre-flight dry-run, configure local (`.env`) and remote (GitHub Actions Secrets & Variables) credentials, and manage **Livehunt** rulesets (`/api/v3/intelligence/hunting_rulesets`) and **Retrohunt** historical corpus jobs (`/api/v3/intelligence/retrohunt_jobs`) as code.

---

## 1. Overview & Operator Pre-Flight Summary

Before configuring credentials or deploying rules, review what Graft provisions and manages in Google Threat Intelligence:

### What Will Be Created & Configured

| Component / Resource | Resource Identifier | Purpose & Operational Rationale |
| :--- | :--- | :--- |
| **GTI v3 Intelligence API** | `https://www.virustotal.com/api/v3` | Provides JSON:API endpoints for Livehunt ruleset CRUD (`/intelligence/hunting_rulesets`), Retrohunt job submission (`/intelligence/retrohunt_jobs`), and user-scoped discovery (`/users/{id}/...`). |
| **Automation Identity** | Dedicated GTI User Account (e.g., `graft-automation@acme.com`) | Standard (**non-admin**) GTI Group member whose 64-character `x-apikey` isolates Graft-managed rulesets and Retrohunt jobs under `owner:self` without colliding with human analysts' personal rules. |
| **Discovery Scope Filter** | `GRAFT_GTI_FILTER="owner:self"` | Scopes `diff`, `apply`, and `pull` strictly to resources owned by the authenticated Graft GTI account (`relationships=owner` + hard `403 OwnershipGuardError` before any `PATCH`/`DELETE`). |
| **Pre-Flight Dry Run** | Non-destructive API & compiler check | Verifies account identity (`GET /api/v3/users/{api_key}`) and submits a transient disabled probe ruleset (`__graft_verify_<uuid8>__`, deleted in `finally:`) to prove YARA-X compilation works. |
| **Environment Export** | `.env` and `gh` CLI commands | Configures local workstation development (`src/graft/engines/gti/.env`) and automated GitHub Actions secrets/variables (`GRAFT_GTI_API_KEY`, `GRAFT_GTI_FILTER`, `GRAFT_GTI_NOTIFICATION_EMAILS`). |

### What Graft Commands & Deploys in GTI

```mermaid
flowchart TD
    RULE["<b>Graft GTI Rule Envelope</b><br/>(rulesets/gti/custom/*.yaml)"]
    COMPILER["<b>GTICompilerAdapter</b><br/>• Partition imports &amp; body<br/>• Inject YARA meta: attribution"]

    RULE --> COMPILER

    COMPILER --> DEP_TYPE{"<b>deployment.type</b><br/>(required)"}
    DEP_TYPE -- "livehunt" --> LH["<b>GTI Livehunt API</b><br/>POST / PATCH / DELETE<br/>/api/v3/intelligence/hunting_rulesets<br/>subtype (required): file | url | domain | ip_address"]
    DEP_TYPE -- "retrohunt (enabled: true)" --> RH["<b>GTI Retrohunt API</b><br/>POST / GET<br/>/api/v3/intelligence/retrohunt_jobs<br/>corpus (required): main | goodware"]
```

| Artifact / Capability | Supported in `gti`? | How Graft Handles It |
| :--- | :---: | :--- |
| **Livehunt Rulesets** (`deployment.type: "livehunt"`) | **Yes** (`custom_rules: true`) | Synchronized via `graft gti diff`, `apply`, and `pull` against `/api/v3/intelligence/hunting_rulesets`. Continuously evaluates incoming GTI submissions in real time across 4 explicit entity streams (`deployment.subtype`: `"file"`, `"url"`, `"domain"`, `"ip_address"`). Syncs `metadata.tags` 1-to-1 with GTI's `attributes.tags`. |
| **Retrohunt Jobs** (`deployment.type: "retrohunt"`) | **Yes** (`custom_rules: true`, `replay_testing: true`) | Configured declaratively under `deployment` (`type: "retrohunt"`, `corpus: "main" \| "goodware"`, optional `start_time`, `end_time`). Kept dormant in Git while `enabled: false` (still linted, syntax-verified, unit-tested, and cataloged) and submitted to `/api/v3/intelligence/retrohunt_jobs` when `enabled: true` is applied. Updating or disabling a Retrohunt rule in Git never deletes or aborts running tasks or historical scan results. Also runnable on-demand via `graft gti test`. |
| **Server-Side Syntax Verification & Dual-Mode Replay** (`verify` / `test`) | **Yes** (`syntax_verification: true`, `replay_testing: true`) | `graft gti verify` validates YARA-X against GTI's real server-side compiler via a transient `enabled: false` probe ruleset deleted in `finally:`. `graft gti test` runs Mode 1 offline synthetic evaluations in memory (zero credentials/quota) and Mode 2 live Retrohunt corpus evaluations (`mode: "retrohunt"`). |
| **Reusable String Datasets** (`datasets/<name>.yaml`) | **No** (`datasets: false`) | GTI's YARA-X runtime does not provide an external lookup table or reference list resource (`DatasetPort` is disabled). GTI rules use 100% native YARA-X without Graft preprocessor hacks; `graft lint` rejects `%<dataset>` tokens in `rulesets/gti/`. |
| **Vendor-Managed Rules** (`rulesets/gti/managed/`) | **No** (`managed_rules: false`) | GTI does not expose vendor-managed curated rulesets on `/intelligence/hunting_rulesets` (`ManagedEnginePort` is disabled). All rulesets visible in a shared GTI organization are user-created (`owner.type == "user"`). |

### Architectural Topologies

Graft supports two operational topologies for Google Threat Intelligence:

- **Mode A: Single-Account Topology (Recommended Standard Setup):**
  - A single dedicated, non-admin GTI User Account (e.g., `graft-automation@acme.com`) authenticated via `GRAFT_GTI_API_KEY` handles both pre-merge PR validation (`graft gti verify` creates a transient disabled probe ruleset `__graft_verify_<uuid8>__` and immediately deletes it in a `finally:` block, producing zero live match notifications) and mainline production synchronization (`graft gti apply --env production --all` scoped to `owner:self`).
- **Mode B: Dual-Account Topology (Optional Segregated Staging & Production Keys):**
  - Organizations that prefer separate API quotas for PR testing vs. production hunting can provision two dedicated non-admin GTI accounts (`GRAFT_GTI_STAGING_API_KEY` for `--env staging` `verify`/`test` and `GRAFT_GTI_PROD_API_KEY` for `--env production` `diff`/`apply`/`pull`). Whenever a tiered key is omitted, Graft automatically falls back to `GRAFT_GTI_API_KEY`.

```mermaid
flowchart TD
    CICD["<b>Graft CI/CD Pipeline</b>"]
    PR["<b>Pull Request (PR Gate)</b>"]
    MAIN["<b>Mainline Merge (main)</b>"]
    STAGING["<b>Staging / PR Verification</b><br/>(GRAFT_GTI_API_KEY or GRAFT_GTI_STAGING_API_KEY)<br/>• Mode 1 Offline Synthetic YARA-X Unit Tests<br/>• Server-Side YARA-X Probe (enabled: false + finally: DELETE)<br/>• Scoped GitOps Diff Preview"]
    PROD["<b>Production GTI Account (owner:self)</b><br/>(GRAFT_GTI_API_KEY or GRAFT_GTI_PROD_API_KEY)<br/>• Synchronize Livehunt Rulesets in-place<br/>• Submit Enabled Retrohunt Jobs non-destructively<br/>• Zero Collision with Human Analyst Rulesets"]

    CICD --> PR
    CICD --> MAIN
    PR --> STAGING
    MAIN --> PROD
```

---

## 2. Account Provisioning & GTI Permissions Setup (Step-by-Step)

### Why Graft Requires a Dedicated Non-Admin GTI Account (`owner:self`)

Unlike Google SecOps (which authenticates via a GCP IAM Service Account), every Google Threat Intelligence API key (`x-apikey`) belongs to a specific **GTI User Account** inside an Organization / Group:

1. **Per-User Ownership vs. Group Visibility:** In a shared GTI Group, all members can view Livehunt rulesets created by colleagues across the group (`/api/v3/intelligence/hunting_rulesets`), while Retrohunt jobs are strictly scoped to the user account that submitted them (`/api/v3/users/{user_id}/retrohunt_jobs`). If you ran Graft with a human analyst's personal API key, Graft's `owner:self` GitOps loop would treat that analyst's personal ad-hoc hunting rulesets as untracked drift.
2. **Group Edit (`relationships.editors`) Nuance:** GTI allows individual rule owners to grant **Group Edit** access on a Livehunt ruleset, which makes that colleague's ruleset editable by every member of the Group—and causes GTI's `GET /api/v3/users/{user_id}/hunting_rulesets` endpoint to return both `{user_id}`'s own rulesets and any group-editable colleague rulesets.
3. **Defense-in-Depth Ownership Guards:** To prevent accidental cross-account mutations, [`GTIDeployerAdapter`](../deployer.py) defaults to `GRAFT_GTI_FILTER="owner:self"`, queries `/api/v3/users/{user_id}/hunting_rulesets` with `relationships=owner`, explicitly skips any resource where `relationships.owner.data.id != current_user_id` (even when a colleague enabled Group Edit), and enforces a hard pre-mutation `403 OwnershipGuardError` before any `PATCH` or `DELETE`.

> [!CAUTION]
> **Never grant Group Administrator privileges to the Graft GTI user account.** A GTI Group Administrator can modify or delete any member's Livehunt rulesets across the entire organization and carries administrative privileges that violate least privilege if the API key is ever exposed. The only trade-off of a dedicated non-admin account is that it cannot directly overwrite an existing brownfield ruleset owned by a colleague unless you import that rule into Git (`GRAFT_GTI_FILTER="all" uv run graft gti pull`), deploy it under the dedicated Graft account, and retire the colleague's legacy copy.

---

### Step 1: Provision the Dedicated Non-Admin GTI User Account

1. Create a service email mailbox or distribution alias in your identity provider for Graft (for example, `graft-automation@acme.com`).
2. Log in to the **Google Threat Intelligence / VirusTotal Enterprise Web UI** (`https://www.virustotal.com/gui/`) as a Group Administrator.
3. Click your **User Avatar (top-right corner) $\rightarrow$ Group / Organization Management $\rightarrow$ Members**.
4. Invite `graft-automation@acme.com` as a **Standard Member (Non-Admin)** and ensure **Livehunt** and **Retrohunt** entitlements/quotas are enabled for the account.
   *(Note: In a single-user evaluation or personal lab tenant where inviting a second account is not possible, you may use your non-admin user account with the default `GRAFT_GTI_FILTER="owner:self"`).*

---

### Step 2: Retrieve the 64-Character GTI API Key (`x-apikey`)

1. Sign in to the Google Threat Intelligence Web UI (`https://www.virustotal.com/gui/`) as the dedicated `graft-automation@acme.com` user.
2. Click the **User Avatar (top-right corner) $\rightarrow$ API Key**.
3. Copy the 64-character lowercase hexadecimal API key.

---

## 3. Pre-Flight Dry-Run Verification

Before saving secrets in GitHub Actions, verify your API key, account identity, and server-side YARA-X compiler connectivity from your terminal:

```bash
# 1. Export your dedicated GTI account API key in your current shell session
export GRAFT_GTI_API_KEY="<PASTE_64_CHAR_GTI_API_KEY_HERE>"

# 2. Verify account identity and confirm non-admin user resolution against GTI v3 API
curl -i -sS \
  -H "x-apikey: ${GRAFT_GTI_API_KEY}" \
  -H "Accept: application/json" \
  "https://www.virustotal.com/api/v3/users/${GRAFT_GTI_API_KEY}"
```

**Expected HTTP Response:**

```http
HTTP/2 200
content-type: application/json; charset=utf-8

{
  "data": {
    "type": "user",
    "id": "graft_automation_user_id",
    "attributes": {
      "status": "active"
    }
  }
}
```

Next, run Graft's server-side YARA-X compiler dry-run and offline synthetic replay test suite against the repository's ruleset:

```bash
# 3. Verify all GTI rules compile cleanly on GTI's server-side YARA-X engine
uv run graft --json gti verify --all

# 4. Run deterministic synthetic test vectors
uv run graft --json gti test
```

---

## 4. Local Workstation & GitHub Actions Configuration

Once the pre-flight dry-run passes, persist your configuration locally and in GitHub Actions:

### 1. Local Workstation Configuration (`src/graft/engines/gti/.env`)

Copy [`.env.example`](../.env.example) to `src/graft/engines/gti/.env` (automatically loaded by Graft at startup and ignored by Git via `.gitignore`):

```bash
cp src/graft/engines/gti/.env.example src/graft/engines/gti/.env
```

Edit `src/graft/engines/gti/.env`:

```bash
export GRAFT_GTI_API_KEY="your-64-char-gti-api-key"
export GRAFT_GTI_FILTER="owner:self"
# Optional: comma-separated recipients for Livehunt / Retrohunt match notifications
export GRAFT_GTI_NOTIFICATION_EMAILS="soc-alerts@acme.com"
```

### 2. GitHub Actions CI/CD Configuration (`gh secret` & `gh variable`)

Register the secret and optional repository variables in your GitHub repository (**Settings $\rightarrow$ Secrets and variables $\rightarrow$ Actions** or via the GitHub CLI):

```bash
# 1. Required: Store the GTI API key as an encrypted GitHub Actions Repository Secret
gh secret set GRAFT_GTI_API_KEY --repo <owner>/<repo>

# 2. Optional: Set remote discovery scope (defaults to "owner:self" if omitted)
gh variable set GRAFT_GTI_FILTER --body "owner:self" --repo <owner>/<repo>

# 3. Optional: Set default notification emails for Livehunt/Retrohunt alerts
gh variable set GRAFT_GTI_NOTIFICATION_EMAILS --body "soc-alerts@acme.com" --repo <owner>/<repo>
```

> [!IMPORTANT]
> **Automatic Cloud Gate Activation:**  
> As soon as `GRAFT_GTI_API_KEY` (or tiered `GRAFT_GTI_STAGING_API_KEY` / `GRAFT_GTI_PROD_API_KEY`) is registered in GitHub Secrets, [`.github/workflows/pr-validation.yml`](../../../../../.github/workflows/pr-validation.yml) (`gti-cloud-gates`) automatically runs server-side YARA-X verification (`graft gti verify`), replay tests (`graft gti test`), and posts a PR reconciliation plan comment (`graft gti diff --env production`), while [`.github/workflows/deploy-production.yml`](../../../../../.github/workflows/deploy-production.yml) reconciles production on every merge to `main` (`graft gti apply --env production --all`). When no GTI secret is configured, CI still runs offline schema linting (`graft lint`) and Mode 1 offline synthetic YARA-X unit tests (`graft gti test` in Gate 5b).

---

## 5. Reference: Secret & Variable Matrix

All variables and secrets strictly use the unified `GRAFT_GTI_` namespace declared in [`src/graft/engines/gti/engine.yaml`](../engine.yaml):

### GitHub Secrets (`${{ secrets.* }}`)

| Secret Name | Target Scope | Provisioned By / Description |
| :--- | :---: | :--- |
| `GRAFT_GTI_API_KEY` | Global / Standard (Mode A) | **Recommended primary secret.** 64-character `x-apikey` for the dedicated non-admin Graft GTI user account. Used by both PR validation (`verify`, `test`, `diff`) and production deployment (`apply`) whenever tiered keys below are unset. |
| `GRAFT_GTI_STAGING_API_KEY` | Staging / PR (Mode B Optional) | Optional staging GTI account API key override used by commands targeting `--env staging` (`graft gti verify`, `graft gti test`). Falls back to `GRAFT_GTI_API_KEY` when unset. |
| `GRAFT_GTI_PROD_API_KEY` | Production / `main` (Mode B Optional) | Optional production GTI account API key override used by commands targeting `--env production` (`graft gti diff`, `graft gti apply`, `graft gti pull`). Falls back to `GRAFT_GTI_API_KEY` when unset. |

### GitHub Variables (`${{ vars.* }}`)

| Variable Name | Target Scope | Value Description |
| :--- | :---: | :--- |
| `GRAFT_GTI_FILTER` | Global / CI | Remote discovery filter: `"owner:self"` (default, strictly scopes to the authenticated Graft GTI account), `"tag:<tag>"`, or `"all"` (for one-time brownfield `pull` inspection). |
| `GRAFT_GTI_NOTIFICATION_EMAILS` | Global / CI | Optional comma-separated default email recipients for Livehunt / Retrohunt match notifications when a rule YAML omits `deployment.notification_emails`. |

### Local Workstation Environment Variables (`.env`)

| Variable Name | Target Scope | Description |
| :--- | :---: | :--- |
| `GRAFT_GTI_API_KEY` | Local / All | Primary 64-character GTI `x-apikey` (fallback for both `staging` and `production` commands). |
| `GRAFT_GTI_STAGING_API_KEY` | Local / Staging | Optional key override for `--env staging` (`verify` and `test`). |
| `GRAFT_GTI_PROD_API_KEY` | Local / Prod | Optional key override for `--env production` (`diff`, `apply`, and `pull`). |
| `GRAFT_GTI_FILTER` | Local / All | Discovery scope (`"owner:self"` default, `"tag:<tag>"`, or `"all"`). |
| `GRAFT_GTI_NOTIFICATION_EMAILS` | Local / All | Optional comma-separated default notification email addresses. |
| `GRAFT_GTI_BASE_URL` | Local / Testing | Optional HTTPS base URL override (defaults to `https://www.virustotal.com/api/v3`; non-HTTPS schemes are rejected). |

---

## 6. Authentication & Isolation Architecture: GitHub Actions (CI/CD) vs. Local Workstation

Graft adheres to a strict **stdlib-first architecture** and makes all GTI v3 JSON:API calls over HTTPS using Python's standard library (`urllib.request`) in [`GTIClient`](../client.py), with automatic key redaction in logs/exceptions and exponential backoff on `429` / `5xx` responses:

```mermaid
flowchart TD
    subgraph REMOTE["Remote Execution (GitHub Actions CI/CD)"]
        direction TB
        RUNNER["GitHub Actions Runner"] --> GH_SEC["Encrypted Repository Secret<br/>(GRAFT_GTI_API_KEY or STAGING/PROD override)"]
        GH_SEC --> RESOLVER_R["GTIConfig.from_env(target)"]
        RESOLVER_R --> CLIENT_R["GTIClient (urllib.request)<br/>Header: x-apikey + User-Agent: graft-dac/0.1.0"]
        CLIENT_R --> GUARD_R["Owner Resolution &amp; Isolation Guard<br/>GET /api/v3/users/{api_key} -> user_id<br/>relationships=owner &amp; OwnershipGuardError"]
        GUARD_R --> GTI_API_R["Google Threat Intelligence v3 API"]
    end

    subgraph LOCAL["Local Developer Workstation (CLI)"]
        direction TB
        DEV["Developer Workstation"] --> ENV_FILE["src/graft/engines/gti/.env<br/>(or root .env / shell export)"]
        ENV_FILE --> RESOLVER_L["GTIConfig.from_env(target)"]
        RESOLVER_L --> CLIENT_L["GTIClient (urllib.request)<br/>Redacts x-apikey on any error"]
        CLIENT_L --> GUARD_L["Owner Resolution &amp; Isolation Guard<br/>GET /api/v3/users/{api_key} -> user_id<br/>relationships=owner &amp; OwnershipGuardError"]
        GUARD_L --> GTI_API_L["Google Threat Intelligence v3 API"]
    end
```

### API Key Resolution Order (`GTIConfig.from_env`)

When executing a CLI command, [`GTIConfig.from_env`](../config.py) resolves the API key based on the target environment (`--env staging` is the default for `verify` and `test`; `--env production` is the default for `diff`, `apply`, and `pull`):

- **1. Environment-Specific Override:** Checks `GRAFT_GTI_STAGING_API_KEY` (when target is `staging`) or `GRAFT_GTI_PROD_API_KEY` (when target is `production`).
- **2. Primary Unified Key Fallback:** If the tiered variable is unset or empty, resolves `GRAFT_GTI_API_KEY`.
- **3. Fail-Fast Offline Guard:** If no key is present, offline commands (`lint`, `render`, and Mode 1 `test`) execute without network calls, while remote commands (`diff`, `apply`, `pull`, or `verify`/`test --require-staging`) fail fast with a clear configuration error.

---

## 7. Configuring `deployment`: Livehunt vs. Retrohunt & 1-to-1 Tag Sync

In Graft, [`BaseDeploymentConfig`](../../../core/models/rule.py) in Core is completely engine-agnostic—every engine defines and validates its own `deployment` block via [`schemas/custom.schema.json`](../schemas/custom.schema.json). The `gti` schema requires `deployment.type` (`"livehunt"` or `"retrohunt"`) and `deployment.enabled` (`boolean`) on every rule—with zero implicit defaults or stream guessing:

### Mode A: Livehunt Deployment (`type: "livehunt"`)

Evaluates newly submitted files, URLs, domains, or IP addresses in real time:

```yaml
deployment:
  type: "livehunt"
  subtype: "domain"
  enabled: true
  daily_limit: 100
  notification_emails:
    - "soc-alerts@acme.com"
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
    - "threat-hunting@acme.com"
```

| Field | Type & Constraints | Description |
| :--- | :--- | :--- |
| `type` | `"retrohunt"` (**required**) | Selects GTI Retrohunt (`/api/v3/intelligence/retrohunt_jobs`). |
| `corpus` | `"main" \| "goodware"` (**required**) | `"main"` scans GTI's historical file submissions (~3–12 months); `"goodware"` scans ~1M NSRL known-good files for false-positive benchmarking. |
| `enabled` | `boolean` (**required**) | Controls job submission. When `false`, the rule remains dormant in Git (linted, syntax-verified, unit-tested, and cataloged without consuming Retrohunt job quota). Setting `enabled: true` and running `graft gti apply` submits the batch scan job to GTI. Setting `enabled: false` after a job runs disables future submissions while **preserving all running tasks and historical scan results** in GTI. |
| `start_time` | ISO-8601 UTC string (optional) | Lower bound for file submission timestamp (`YYYY-MM-DDTHH:MM:SSZ`), converted to Unix epoch seconds in GTI's `attributes.time_range.start`. |
| `end_time` | ISO-8601 UTC string (optional, requires `start_time`) | Upper bound for file submission timestamp (`YYYY-MM-DDTHH:MM:SSZ`, must be strictly after `start_time`), converted to Unix epoch seconds in GTI's `attributes.time_range.end`. |
| `notification_emails` | `array[string]` (optional) | Email addresses notified when the Retrohunt job finishes (`attributes.notification_email`). |

> [!NOTE]
> Retrohunt rules always scan historical files and cannot declare Livehunt-only fields (`subtype`, `daily_limit`). We recommend prefixing Livehunt rule names/files with `lh_` (e.g., [`lh_rogue_ssl_certificate_brand_impersonated.yaml`](../../../../../rulesets/gti/custom/lh_rogue_ssl_certificate_brand_impersonated.yaml)) and Retrohunt rules with `rh_` (e.g., [`rh_corporate_secret_key_leak_swept.yaml`](../../../../../rulesets/gti/custom/rh_corporate_secret_key_leak_swept.yaml)).

### 1-to-1 `metadata.tags` Synchronization

Graft does **not** inject a hidden `"graft"` tag into your GTI rulesets. Because ownership isolation is handled by the dedicated Graft user account (`GRAFT_GTI_FILTER="owner:self"`), `metadata.tags` in your rule YAML is synchronized **1-to-1** with GTI's Livehunt `attributes.tags` (and embedded as `tags = "..."` in YARA `meta:` for lossless round-tripping across both Livehunt and Retrohunt):

- All tags across Graft (`metadata.tags` in custom rules, managed rules, and datasets) must match `^[a-z0-9_/:-]{1,32}$` (lowercase letters, digits, hyphens `-`, underscores `_`, colons `:`, and forward slashes `/`, up to 32 characters per tag).
- Avoid repeating attributes already captured in dedicated envelope fields (`engine`, `deployment.type`, `deployment.subtype`, or `metadata.mitre` tactics). Use `metadata.tags` for organizational, domain, threat-family, or telemetry grouping (e.g., `["acme", "phishing", "tls", "x509"]` or `["americas", "banking-trojan", "breeze-comet", "financial"]`).

---

## 8. Authoring Native YARA-X `logic` & Synthesis (`graft gti render`)

### 1. `$LOGIC_IMPORTS` + `$LOGIC_BODY` Separation

Analysts write only top-level `import "<module>"` statements (`import "vt"`, `import "pe"`, `import "elf"`, `import "math"`, etc.) followed by `strings:` (optional) and `condition:` in `logic`—never an outer `rule <name> { meta: ... }` wrapper:

```yaml
logic: |
  import "vt"

  condition:
    vt.net.domain.root != "acme.com" and
    defined vt.net.domain.https_certificate.subject.common_name and
    (
      vt.net.domain.raw matches /\bacme\b/i or
      vt.net.domain.https_certificate.subject.common_name matches /\bacme\b/i or
      (
        vt.net.domain.https_certificate.subject.organization matches /\bacme\b/i and
        for any name in vt.net.domain.https_certificate.subject_alternative_name : (
          name == vt.net.domain.raw
        )
      )
    )
```

### 2. Native YARA-X Synthesis (`graft gti render`)

Running `uv run graft gti render` partitions top-level `import "..."` lines above the `rule <rule_name> { ... }` declaration and injects Graft's attribution and MITRE ATT&CK tags into the YARA `meta:` section:

```yara
import "vt"

rule lh_rogue_ssl_certificate_brand_impersonated {
  meta:
    graft_id = "8f14e45f-ceea-467a-a124-000000000002"
    description = "Matches external domains presenting X.509 SSL/TLS certificates spoofing ACME Financial in Subject or SAN"
    owners = "Threat Intelligence, Detection Engineering"
    mitre_tactic = "resource-development, stealth"
    mitre_technique = "T1587.003, T1036.005"
    tags = "acme, phishing, tls, x509"

  condition:
    // Exclude legitimate ACME Financial corporate root domain
    vt.net.domain.root != "acme.com" and
    defined vt.net.domain.https_certificate.subject.common_name and
    (
      // Match lookalike domain names or X.509 certificate Subject CN / Org + SAN spoofing ACME
      vt.net.domain.raw matches /\bacme\b/i or
      vt.net.domain.https_certificate.subject.common_name matches /\bacme\b/i or
      (
        vt.net.domain.https_certificate.subject.organization matches /\bacme\b/i and
        for any name in vt.net.domain.https_certificate.subject_alternative_name : (
          name == vt.net.domain.raw
        )
      )
    )
}
```

---

## 9. Verification & Dual-Mode Replay Testing (`graft gti verify` & `graft gti test`)

### 1. Server-Side YARA-X Verification (`graft gti verify`)

GTI does not expose a dedicated stateless syntax-check endpoint. When `uv run graft --json gti verify` runs:

1. Graft performs an instant local structural check (non-empty `condition:`, balanced `{}` and `()`).
2. If a GTI API key is configured (`GRAFT_GTI_STAGING_API_KEY` or `GRAFT_GTI_API_KEY`), [`GTICompilerAdapter`](../compiler.py) submits a transient **disabled** ruleset (`POST /api/v3/intelligence/hunting_rulesets` with `enabled: false`, explicit `match_object_type`, and name `__graft_verify_<uuid8>__`) to invoke GTI's real server-side YARA-X compiler.
3. A `finally:` block immediately executes `DELETE /api/v3/intelligence/hunting_rulesets/{id}`, guaranteeing zero leftover probe rulesets or live alerts. Any remote compiler line number is adjusted back to the local YAML `logic` line offset.

### 2. Dual-Mode Replay Testing (`graft gti test`)

[`GTIReplayAdapter`](../replay.py) supports two test vector modes in the `tests:` block:

#### Mode 1: Offline Synthetic Unit Tests (Default — Fast, Deterministic, Zero Quota)

Evaluates `vt.net.*`, `vt.metadata.*`, `vt.behaviour.*`, `filesize` (including `KB`/`MB`/`GB` literals), `defined`, `for any/all <item> in <list> : (...)`, regex `matches /.../i`, and `strings:` (`sample_text`, regex strings `/.../`, `#var` occurrence counts, and `any/all of ($prefix_*)`) in memory against synthetic event payloads without requiring API credentials:

```yaml
tests:
  - id: "match_rogue_domain_with_acme_ssl_common_name"
    description: "External domain presenting an HTTPS certificate with ACME in Subject Common Name triggers a match"
    expect: 1
    events:
      - timestamp: "2026-10-15T12:00:00Z"
        payload:
          vt.net.domain.root: "login-acme-wealth.test"
          vt.net.domain.raw: "sso.login-acme-wealth.test"
          vt.net.domain.https_certificate.subject.common_name: "sso.acme.com"
          vt.net.domain.https_certificate.subject.organization: "ACME Financial Corp"
          vt.net.domain.https_certificate.subject_alternative_name:
            - "sso.login-acme-wealth.test"
```

For file/Retrohunt rules with a `strings:` section and `filesize`, pass `sample_text` and `filesize` in `payload`:

```yaml
tests:
  - id: "match_leaked_acme_script_with_private_key"
    description: "Python script under 5MB containing acme.com and a PEM private key header triggers a match"
    expect: 1
    events:
      - timestamp: "2026-10-15T12:00:00Z"
        payload:
          filesize: 40960
          vt.metadata.file_type: "vt.FileType.PYTHON"
          vt.metadata.analysis_stats.undetected: 58
          sample_text: "ENDPOINT = 'https://api.acme.com/v1/payments'\nKEY = '-----BEGIN PRIVATE KEY-----'"
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

Graft submits `POST /api/v3/intelligence/retrohunt_jobs`, polls `GET /api/v3/intelligence/retrohunt_jobs/{id}` until `status` reaches `"finished"` or `"aborted"`, asserts `num_matches == expect`, and deletes the transient Retrohunt job in a `finally:` block. If credentials are absent locally, `mode: "retrohunt"` vectors emit `[WARNING]` and skip cleanly (exit `0`) unless `--require-staging` is passed.

---

## 10. Custom Rule Reconciliation, Non-Destructive Retrohunt Lifecycle, & Drift Self-Healing

Unlike traditional SIEMs with a single rule endpoint, Google Threat Intelligence separates real-time hunting (`hunting_rulesets`) from historical corpus batch jobs (`retrohunt_jobs`). [`CustomRuleReconciler`](../../../core/reconciler.py) and [`GTIDeployerAdapter`](../deployer.py) reconcile both resource types through a unified, non-destructive lifecycle:

```mermaid
sequenceDiagram
    autonumber
    participant Core as CustomRuleReconciler
    participant Adapter as GTIDeployerAdapter
    participant API as GTI v3 REST API

    Note over Core,API: 1. Resolve Authenticated User & Fetch Owned State (owner:self)
    Core->>Adapter: list_rules()
    Adapter->>API: GET /api/v3/users/{api_key}
    API-->>Adapter: Authenticated user_id
    Adapter->>API: GET /api/v3/users/{user_id}/hunting_rulesets?relationships=owner
    API-->>Adapter: Owned Livehunt rulesets (non-owned Group Edit rules skipped)
    Adapter->>API: GET /api/v3/users/{user_id}/retrohunt_jobs?relationships=owner
    API-->>Adapter: Owned Retrohunt jobs
    Adapter-->>Core: Tuple of deconstructed remote RuleEnvelopes

    Note over Core,API: 2. In-Memory Diffing & Dormant Retrohunt Filtering
    Core->>Adapter: rule_content_matches(desired, remote) & are_deployments_equal(desired, remote)

    alt Livehunt Rule (deployment.type == "livehunt")
        alt New Livehunt Rule
            Core->>Adapter: create_rule(rule)
            Adapter->>API: POST /api/v3/intelligence/hunting_rulesets
        else Modified Livehunt Rule (Content, subtype, enabled, limit, emails, or tags)
            Core->>Adapter: update_rule(rule)
            Adapter->>Adapter: Verify owner_id == user_id (403 OwnershipGuardError if mismatch)
            Adapter->>API: PATCH /api/v3/intelligence/hunting_rulesets/{id}
        end
    else Retrohunt Rule (deployment.type == "retrohunt")
        alt Dormant in Git (enabled: false)
            Core->>Adapter: should_deploy_rule(rule) -> False
            Note over Core,Adapter: Kept dormant in Git (0 Retrohunt quota consumed;<br/>existing historical jobs/results in GTI are never deleted)
        else Active Trigger (enabled: true)
            Core->>Adapter: create_rule(rule) / update_rule(rule)
            Adapter->>API: POST /api/v3/intelligence/retrohunt_jobs
        end
    end
```

### Key Reconciliation Guarantees

1. **In-Place Livehunt Updates (`PATCH /intelligence/hunting_rulesets/{id}`):**
   - Updating YARA-X logic, `metadata.tags`, `subtype`, `enabled`, `daily_limit`, or `notification_emails` updates the existing GTI ruleset in-place, preserving its GTI ruleset ID (`https://www.virustotal.com/gui/hunting/livehunt/rulesets/<id>`) and historical match notifications.
2. **Non-Destructive Retrohunt Job Lifecycle:**
   - When a Retrohunt rule is committed with `enabled: false`, `should_deploy_rule()` returns `False`: the rule is validated by `graft lint`, compiled via `graft gti verify`, tested via `graft gti test`, and exported to MITRE Navigator without submitting a scan job.
   - When flipped to `enabled: true` and applied, Graft submits `POST /api/v3/intelligence/retrohunt_jobs`.
   - When subsequently updated or flipped back to `enabled: false`, Graft **never calls `DELETE` or `/abort`** on existing Retrohunt jobs, preserving all historical scan match results in GTI.
3. **Catalog Health Resolution (`enabled` | `silent` | `disabled`):**
   - In `graft export catalog` and `graft export matrix`, [`resolve_gti_deployment_status`](../compiler.py) classifies a GTI rule as:
     - `disabled` when `deployment.enabled` is `false`.
     - `enabled` when `deployment.enabled` is `true` and notification emails are configured (either in `deployment.notification_emails` or `GRAFT_GTI_NOTIFICATION_EMAILS`).
     - `silent` when `deployment.enabled` is `true` with no notification emails configured (matches are recorded silently in the GTI UI / IOC Stream without sending email alerts).

### Out-of-Band Drift Detection & Self-Healing

If an analyst manually edits a Graft-managed Livehunt ruleset in the GTI Web UI (changing its YARA condition, tags, daily limit, or enabled state):

1. **Drift Detection:** Running `uv run graft gti diff --all` detects the discrepancy and exits with code `2`:
   ```text
   === Custom Rules Diff ===
   [~] Custom rule to update: lh_rogue_ssl_certificate_brand_impersonated (ID: 8f14e45f-ceea-467a-a124-000000000002)
   ```
2. **Authoritative Self-Healing:** Running `uv run graft gti apply --all` patches the ruleset back to the exact YARA-X logic, tags, and deployment parameters declared in Git:
   ```text
   Applied custom rules: 0 created, 1 updated.
   ```

---

## 11. Brownfield Engine Onboarding & Reverse Sync (`graft gti pull`)

When adopting Graft in an organization that already has Livehunt rulesets in Google Threat Intelligence, you can import existing rulesets directly into 5-block YAML envelopes without manual copy-pasting:

1. **Execute Reverse Sync:**
   - **To pull rulesets already owned by the Graft account (`owner:self` default):**
     ```bash
     uv run graft gti pull --env production
     ```
   - **To migrate legacy colleague-owned rulesets from a shared GTI Group into Git:**
     Temporarily override `GRAFT_GTI_FILTER` to pull rulesets matching a migration tag (or `"all"`):
     ```bash
     GRAFT_GTI_FILTER="tag:migration" uv run graft gti pull --env production
     ```
   [`deconstruct_yara_rule`](../compiler.py) strips the outer `rule <name> { ... }` wrapper, preserves custom analyst `meta:` key-values while extracting Graft metadata (`graft_id`, `description`, `owners`, `mitre_tactic`, `mitre_technique`, `tags`), assigns a deterministic UUIDv5 (`uuid5(NAMESPACE_DNS, f"graft.gti.{name}")`) if `graft_id` was absent, normalizes rule names to `<= 64` snake_case characters, auto-upgrades any deprecated MITRE tactics/techniques, and writes `rulesets/gti/custom/*.yaml`.
2. **Verify & Enrich:**
   ```bash
   uv run graft lint rulesets/gti/
   ```
   Prefix imported filenames and `metadata.name` with `lh_` or `rh_`, enrich operational runbooks (`context`, `triage`, `response`), and add positive/negative synthetic test vectors (`/scaffold-tests`).
3. **Deploy Under the Dedicated Graft Account & Retire Legacy Copies:**
   ```bash
   uv run graft gti apply --env production --all
   ```
   Once deployed under the dedicated `graft-automation@acme.com` account (`owner:self`), disable or delete the colleague's legacy duplicate in the GTI UI.

For full architectural details, see the **[Engine Adoption & Lifecycle Guide](../../../../../docs/operators/adoption.md)**.

---

## 12. CLI Operations Reference

```bash
# 1. Scaffold a new GTI custom rule (use lh_ for Livehunt, rh_ for Retrohunt)
uv run graft gti new lh_brand_sso_portal_impersonated

# 2. Validate YAML schemas, deployment type/subtype constraints, and MITRE mappings offline
uv run graft --json lint rulesets/gti/

# 3. Render synthesized YARA-X rules offline (with injected meta: attribution)
uv run graft --json gti render --all

# 4. Verify YARA-X syntax against GTI's server-side compiler (transient disabled ruleset probe)
uv run graft --json gti verify --all

# 5. Execute offline synthetic unit test vectors (and any live mode: "retrohunt" vectors)
uv run graft --json gti test

# 6. Diff and apply Livehunt rulesets and enabled Retrohunt jobs (scoped to owner:self)
uv run graft --json gti diff --all
uv run graft --json gti apply --all

# 7. Pull existing Livehunt rulesets & Retrohunt jobs into 5-block YAML envelopes
uv run graft --json gti pull
```

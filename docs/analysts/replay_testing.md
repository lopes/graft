# Synthetic Replay Testing & Quarantine Harness

> [!NOTE]
> **Engine-Specific Replay Implementations (`ReplayHarnessPort`):**
> - **Google Threat Intelligence (`gti` — Active Out-of-the-Box):** [`GTIReplayAdapter`](../../src/graft/engines/gti/replay.py) provides dual-mode replay testing today: **Mode 1 (Offline Synthetic YARA-X Unit Evaluation)** runs 100% offline in memory with zero API credentials (evaluating `vt.*`, `filesize`, `defined`, `for any/all`, regexes, `#var` counts, and `strings:` / `sample_text`, and runs automatically in CI Gate 5b on every PR), while **Mode 2 (`mode: "retrohunt"`)** submits an on-demand Retrohunt job against GTI's `"main"` or `"goodware"` corpus and cleans it up in a `finally:` block.
> - **Google SecOps (`secops` — Quarantined Staging Evaluation):** [`SecOpsReplayAdapter`](../../src/graft/engines/secops/replay.py) pre-synchronizes referenced local datasets (`%<name>.value`) to a dedicated Staging SecOps tenant, deploys a temporary non-alerting quarantine rule, injects synthetic UDM events, evaluates detections over the bounding time window, and tears down the temporary rule in `finally:`.

Static syntax linting validates query structure, but cannot verify whether complex regular expressions, multi-event time windows, or outcome calculations match true attack patterns. Graft addresses this with an automated **Synthetic Replay Harness** (`ReplayHarnessPort`).

---

## 1. The Replay Testing Lifecycle

When `graft <engine> test` is executed, the engine's replay adapter pre-synchronizes any referenced local datasets (`datasets/<name>.yaml`) to the staging tenant, deploys a temporary quarantine rule, ingests synthetic test events into the staging instance, triggers an ad-hoc evaluation over the test time window, asserts the detection count against `test.expect`, and guarantees teardown cleanup.

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Developer / CI
    participant Graft as Graft Replay Harness (ReplayHarnessPort)
    participant API as Staging SIEM API

    Dev->>Graft: graft <engine> test [rule]
    Graft->>API: Pre-Sync Referenced Local Datasets (%<name>.value)
    API-->>Graft: Staging Data Tables created or updated
    Graft->>API: Create Quarantined Rule (enabled=True, alerting=False)
    API-->>Graft: Return temporary rule_id
    Note over Graft,API: Rule is quarantined: zero live alerts or SOC contamination

    Graft->>API: Ingest Synthetic Events (test.events[])
    API-->>Graft: Events written to staging buffer

    Graft->>API: Evaluate Rule Over Bounding Time Window
    API-->>Graft: Return detectionCount & detections[]

    critical Teardown Cleanup
        Graft->>API: Delete Temporary Rule (rule_id)
        API-->>Graft: Rule permanently removed
    end

    Graft->>Dev: Assert detectionCount == test.expect (PASS/FAIL)
```

---

## 2. Quarantine Safeguards & Production Isolation

To prevent synthetic testing from contaminating production alert queues or skewing SOC metrics, replay adapters enforce three layers of protection:

1. **Explicit Quarantine Configuration:**
   - Temporary rule name: `graft_test_<rule_name>_<uuid8>`.
   - `alerting = False`: Rule matches never trigger notification pipelines, webhooks, or SOC incident creation.
   - `enabled = True`: Rule is active only for the duration of the isolated evaluation window and deleted immediately afterward.
2. **Scoped Time-Window Evaluation:**
   - Ad-hoc evaluation runs strictly over the bounding timestamp window defined by the synthetic test events (`min(timestamp)` to `max(timestamp)`).
3. **Guaranteed `finally` Cleanup:**
   - Rule deletion is wrapped in a Python `finally:` block. Even if the evaluation API returns an error or times out, the temporary rule is purged.

---

## 3. Environment Topologies: Staging vs. Single-Tenant Guard

### Multi-Tenant Enterprise Topology (Required for Replay Testing)

Staging and Production point to two physically separate SIEM instances:

- `GRAFT_<ENGINE>_STAGING_*` (e.g., `GRAFT_SECOPS_STAGING_*`): Used for synthetic replay testing and pre-merge compiler verification.
- `GRAFT_<ENGINE>_PROD_*` (e.g., `GRAFT_SECOPS_PROD_*`): Production operational environment.

### Single-Tenant Production Guard

Because synthetic replay testing injects test events and creates temporary rules, replay adapters enforce a strict production tenant guard. If staging coordinates are omitted or resolve to the same tenant instance as Production (for example, the same `(project_id, location, instance_id)` in `SecOpsReplayAdapter`), Graft refuses to inject synthetic events into Production:

- Without `--require-staging` (default): Emits `[WARNING] Skipping replay tests: Replay tests require a dedicated staging tenant and cannot run against production coordinates.` and exits `0` (graceful degradation).
- With `--require-staging`: Emits `Error: --require-staging was specified but only production tenant is configured.` and exits `1`.

---

## 4. CLI Invocations & Selective Testing

```bash
# Run replay tests across all custom rules for an engine (e.g., secops)
graft secops test

# Test only rules modified in the current Git branch or working tree (ideal for fast PRs)
graft secops test --changed-only

# Target a specific rule file
graft secops test rulesets/secops/custom/workspace_nrd_email_opened.yaml

# Enforce hard failure if staging credentials are not configured (required in CI/CD)
graft secops test --require-staging
```

---

## 5. Graceful Degradation in Local & CI Environments

Developers without cloud credentials or working offline must not be blocked from running local test suites. Graft enforces a strict graceful degradation contract:

| Scenario | CLI Invocation | Exit Code | Output Behavior |
| :--- | :--- | :---: | :--- |
| **No tests defined** | `graft <engine> test` | `0` | `No replay test vectors found in target rules.` |
| **Tests defined, no staging creds** | `graft <engine> test` | `0` | `[WARNING] Skipping replay tests: Staging tenant not configured (<reason>).` |
| **Strict CI Gate** | `graft <engine> test --require-staging` | `1` | `Error: --require-staging was specified but <reason>` |
| **All assertions match** | `graft <engine> test` | `0` | `[PASS] <rule_name> :: <test_id>` + `Replay test results: <passed> passed, 0 failed.` |
| **Detection count mismatch** | `graft <engine> test` | `1` | `[FAIL] <rule_name> :: <test_id>` + `Replay test results: <passed> passed, <failed> failed.` |


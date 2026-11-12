---
name: scaffold-tests
description: >
  Generate positive (`expect: 1`) and negative (`expect: 0`) synthetic event
  test vectors in a custom rule's `tests` block by analyzing its `logic` query,
  preserving all other envelope blocks untouched. Use when the user invokes
  `/scaffold-tests <rule_path>` or asks to generate synthetic test vectors for a Graft rule.
---

# Graft Synthetic Test Vector Scaffolder (`tests`)

You are a Senior Threat Detection Engineer operating inside the **Graft** Detection-as-Code platform. Your single responsibility in this skill is to read the authored **`logic`** block of a custom rule YAML file and populate its **`tests`** block with realistic positive (`expect: 1`) and negative (`expect: 0`) synthetic event vectors, while keeping **`metadata`**, **`logic`**, **`deployment`**, and **`runbook`** verbatim.

Before generating test vectors, ground your decisions in:
- [Rule Authoring Guide](../../../docs/analysts/rule_authoring.md)
- [Synthetic Replay Testing Guide](../../../docs/analysts/replay_testing.md)
- [Base Custom Rule Schema](../../../src/graft/core/schemas/base_custom.schema.json)
- [Reference SecOps Custom Rule (`workspace_nrd_email_opened.yaml`)](../../../rulesets/secops/custom/workspace_nrd_email_opened.yaml)
- [Reference GTI Livehunt Rule (`lh_rogue_ssl_certificate_brand_impersonated.yaml`)](../../../rulesets/gti/custom/lh_rogue_ssl_certificate_brand_impersonated.yaml)
- [Reference GTI Retrohunt Rule (`rh_corporate_secret_key_leak_swept.yaml`)](../../../rulesets/gti/custom/rh_corporate_secret_key_leak_swept.yaml)

---

## 1. Execution Workflow

```mermaid
flowchart TD
    IN["Analyst Input: /scaffold-tests &lt;rule_path&gt;"] --> READ["Read target YAML rule file"]
    READ --> GUARD{"Has authored custom logic?"}
    GUARD -->|"Managed rule or default engine stub"| ABORT["Stop and inform analyst:<br/>Author custom logic before generating tests"]
    GUARD -->|"Valid custom query"| PARSE["Extract all event variables, predicates,<br/>joins, regexes, and match time windows"]
    PARSE --> GEN["Construct &gt;=1 positive (match_*, expect: 1)<br/>and &gt;=1 negative (ignore_*, expect: 0) vectors"]
    GEN --> WRITE["Update ONLY the tests block in YAML<br/>(Preserve metadata, logic, deployment, runbook)"]
    WRITE --> LINT["Run: uv run graft lint &lt;rule_path&gt;<br/>(+ uv run graft gti test &lt;rule_path&gt; for gti rules)"]
```

### Step 1: Pre-Flight Guards

1. Read the target YAML file.
2. **Reject Registered Managed Rules:** If the file contains a `managed:` block instead of `logic:`, stop and inform the analyst that vendor-managed rules do not expose query logic locally for predicate-driven vector generation.
3. **Reject Untouched Stub Logic:** If `logic` still contains the default `graft new rule` placeholder (`$e.metadata.event_type = "USER_LOGIN"` for `secops` or bare `vt.net.url.new_url` for `gti` with no additional predicates), stop and instruct the analyst to author the detection query in `logic` first.

---

## 2. Strict Block Ownership Guardrails

- **Touch ONLY the `tests` block.**
- **Never modify `metadata`, `logic`, `deployment`, or `runbook`.** Preserve their exact content and formatting.

---

## 3. Test Vector Construction Rules

### Schema Constraints (`base_custom.schema.json`)
Every item in `tests` must satisfy:
- `id` *(string, required)*: Snake_case identifier matching `^[a-z0-9_]+$` (`1..64` characters).
  - Prefix positive test IDs with `match_` (e.g., `match_service_account_key_creation`, `match_opened_nrd_email`, `match_rogue_domain_with_acme_ssl_common_name`).
  - Prefix negative test IDs with `ignore_` (e.g., `ignore_service_account_listing`, `ignore_standard_unopened_email`, `ignore_legitimate_acme_corporate_domain`).
- `description` *(string, required)*: Clear, single-sentence statement of what the test vector verifies (`1..256` characters).
- `expect` *(integer, required)*: `1` (or exact expected match count) for positive vectors; `0` for negative vectors.
- `events` *(non-empty list of objects, required)*:
  - `timestamp` *(string, required)*: Valid ISO-8601 UTC timestamp (`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`, e.g., `"2026-09-17T15:00:00Z"`).
  - `payload` *(non-empty object, required)*: Dictionary mirroring the target engine's native event schema (Chronicle UDM field hierarchy for `secops`; `vt.*` entity attributes, `filesize`, `sample_text`, or `mode: "retrohunt"` + `corpus` for `gti`).

### Predicate & Join Fidelity
1. **Positive Vector (`id: "match_<scenario>"`, `expect: 1`):**
   - **Google SecOps (`secops` — YARA-L 2.0 UDM Vectors):**
     - Trace every event variable required by the `condition:` section (e.g., `$mail and $whois` requires two events in `events`, one matching `$mail` and one matching `$whois`).
     - Populate every UDM field path referenced in `events:` predicates, comparisons, `nocase`, or `re.regex` expressions so all conditions evaluate to `true`.
     - When `logic` joins multiple events on a shared placeholder variable (e.g., `$domain` or `$principal_user`) over a `match:` window (e.g., `over 1h`), ensure the joined field values match identically across events and their `timestamp` values fall within the time window.
     - Include fields referenced in the `outcome:` section (e.g., `principal.user.userid`, `target.resource.name`) using realistic, non-sensitive enterprise example values (`corp.example.com`, RFC 5737 documentation IPs `192.0.2.x` / `198.51.100.x` / `203.0.113.x`).
   - **Google Threat Intelligence (`gti` — YARA-X Mode 1 Offline & Mode 2 Retrohunt Vectors):**
     - For **Mode 1 Offline Synthetic Unit Tests** (evaluated in memory by `uv run graft gti test` with zero API credentials): populate the exact `vt.net.*`, `vt.metadata.*`, or `vt.behaviour.*` dotted keys referenced in `condition:` (including list values for `for any/all <item> in <list> : (...)` quantifiers and integer byte values for `filesize` comparisons against `KB`/`MB`/`GB`).
     - Whenever the GTI rule defines a `strings:` section (`$str_*`, regex `/.../`, `#var` occurrence counts, or `any/all of ($prefix_*)`), include a synthetic `sample_text` string in `payload` containing the required string/regex patterns.
     - For **Mode 2 On-Demand Live Retrohunt Corpus Tests** (optional): set `mode: "retrohunt"` and `corpus: "goodware" | "main"` (with optional `time_range: {start, end}`) in `payload`.
2. **Negative Vector (`id: "ignore_<scenario>"`, `expect: 0`):**
   - Clone the realistic telemetry structure of the positive vector, but mutate a decisive predicate so the rule must not trigger (for `secops`: a benign `product_event_type` such as read/list instead of create, an unopened email instead of opened, or `security_result.action = "BLOCK"`; for `gti`: a legitimate corporate root domain `vt.net.domain.root: "acme.com"`, missing `strings:` pattern in `sample_text`, `filesize` exceeding the threshold, or non-matching `vt.metadata.file_type`).
   - State the exact negated condition in `description` so reviewers immediately understand why `expect: 0` holds.

---

## 4. Mandatory Validation Gate

After updating the `tests` block in the YAML file:

1. Run offline schema validation:
   ```bash
   uv run graft lint <rule_path>
   ```
2. For Google Threat Intelligence (`rulesets/gti/custom/*.yaml`) rules, also execute the deterministic offline YARA-X replay harness to verify all Mode 1 `match_*` (`expect: 1`) and `ignore_*` (`expect: 0`) vectors pass in memory:
   ```bash
   uv run graft gti test <rule_path>
   ```
3. If `graft lint` or `graft gti test` reports any error, fix the `tests` block and re-run until it exits `0`.
4. Summarize the generated `match_*` and `ignore_*` test vectors and their verified predicates for the analyst.

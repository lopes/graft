---
name: review-rule
description: >
  Perform a read-only 5-block quality, security, and schema audit on one or more
  Graft detection rules (`metadata`, `logic`, `deployment`, `runbook`, `tests`),
  running `graft lint` and outputting a structured PASS / WARN / FAIL report
  with concrete suggested fixes. Use when the user invokes `/review-rule`.
disable-model-invocation: true
---

# Graft Detection Rule Reviewer (`review-rule`)

You are a Principal Threat Detection Engineer conducting a rigorous, high-signal peer review of one or more **Graft** detection rules. By default, this skill is **strictly read-only**: you run deterministic validation (`uv run graft lint`) and audit all envelope blocks against Graft's engineering standards, producing a structured report with concrete remediation snippets without mutating any files unless the analyst explicitly asks you to apply the fixes.

Ground every review finding in:
- [Rule Authoring Guide](../../../docs/analysts/rule_authoring.md)
- [Synthetic Replay Testing Guide](../../../docs/analysts/replay_testing.md)
- [Base Custom Rule Schema](../../../src/graft/core/schemas/base_custom.schema.json)
- [Base Managed Rule Schema](../../../src/graft/core/schemas/base_managed.schema.json)

---

## 1. Execution Workflow

```mermaid
flowchart TD
    IN["Analyst Input: /review-rule [path_or_dir]"] --> TARGET{"Target Specified?"}
    TARGET -->|"Explicit file or directory"| USE["Use provided rule path(s)"]
    TARGET -->|"No path provided"| GIT["Find modified/untracked YAML files<br/>under rulesets/ via git status/diff"]
    USE --> LINT["Run: uv run graft lint &lt;target&gt;"]
    GIT --> LINT
    LINT --> AUDIT["Audit all blocks against Graft standards:<br/>1. metadata  2. logic  3. deployment/managed  4. runbook  5. tests"]
    AUDIT --> REPORT["Output structured PASS / WARN / FAIL report<br/>with exact YAML/query remediation snippets"]
```

### Step 1: Resolve Target Rule(s) & Run Deterministic Linter

1. If the analyst specifies a file path or directory, review that target. If no path is provided, inspect modified and untracked rule files under `rulesets/` (excluding `_archived/` and `managed/index.yaml`).
2. Execute the offline linter:
   ```bash
   uv run graft lint <target>
   ```
3. Record all schema, MITRE ATT&CK STIX taxonomy, and repository-wide uniqueness findings.

---

## 2. Five-Block Review Checklist

Evaluate each rule across all blocks and classify every check as `PASS`, `WARN`, or `FAIL`:

### Block 1: `metadata`
- **Naming (`<subject>_<fact>`):**
  - Does `metadata.name` (and filename stem) follow `<subject>_<fact>` ending in a past-tense verb (`created`, `opened`, `granted`, `matched`, `flushed`)?
  - Flag any filler prepositions (`_to_`, `_of_`, `_or_`, `_in_`, `_with_`, `_for_`, `_at_`, `_by_`, `_via_`, `_from_`) or speculative words (`possible`, `suspicious`, `potential`, `activity`, `detected`, `attempt`, `success`, `alert`).
- **Description:**
  - Is `metadata.description` $\le 128$ characters, non-conversational, and accurately aligned with what `logic` actually detects?
  - Flag leftover `graft new rule` stubs (`"Detection rule for ..."`).
- **Owners:**
  - Is `metadata.owners` populated with a real owner or team (flagging generic placeholders if left unreviewed)?
- **MITRE ATT&CK Mapping:**
  - Are tactics and techniques valid in `src/graft/data/mitre_attack.json`?
  - Does the mapping use the **most specific sub-technique** (`TXXXX.XXX`) that reflects the telemetry in `logic`?
  - Flag leftover `graft new rule` stub mappings (`execution: ["T1059.001"]`) when the rule is unrelated to PowerShell.
- **Tags:**
  - Does `metadata.tags` contain 2–3 broad, reusable lowercase platform/surface labels (e.g., `gcp`, `iam`, `workspace`, `email`, `whois`, `gcti`, `network`)?
  - Flag tags that duplicate the engine name (`secops`), rule type (`custom`, `managed`), or MITRE tactic names (`initial-access`, `persistence`).
- **References:**
  - Do `metadata.references` cite the matching MITRE technique URLs and/or relevant vendor docs or threat research (flagging leftover `T1059/001` stub URLs)?

### Block 2: `logic` *(Custom Rules Only)*
- **Stub Detection:** Flag immediately (`FAIL`) if `logic` still contains the default `USER_LOGIN` stub from `graft new rule`.
- **Semantic Alignment:** Does the query actually detect the behavior claimed in `metadata.description` and `runbook.context`?
- **Query Hygiene & Performance:**
  - Are event variable names descriptive (`$mail`, `$whois`, `$iam` rather than `$e1`, `$e2`)?
  - Are multi-event joins selective and bounded by an explicit, justified `match:` time window?
  - Are magic numbers (such as `604800` seconds or numeric `product_event_type` codes) explained with inline comments?
  - Are unanchored regexes or overly broad predicates likely to cause high false-positive volume?
  - If `logic` references a local dataset in `datasets/<name>.yaml`, verify it uses `%<name>.value` and literal string membership (`in %<name>.value`, never `in cidr` or `in regex`).
  - Verify `logic` does **not** include an outer `rule <name> { meta: ... }` wrapper (Graft synthesizes the wrapper automatically for SecOps).

### Block 3: `deployment` / `managed`
- **Custom Rules (`deployment`):**
  - Check `enabled`, `alerting`, and `run_frequency`.
  - Emit a `WARN` if a newly scaffolded or high-noise rule sets `alerting: true` without tuned exclusions or high-confidence predicates.
- **Registered Managed Rules (`managed`):**
  - Verify `managed.id` exists in `rulesets/<engine>/managed/index.yaml` and that `metadata.name` / `runbook` accurately describe that specific vendor ruleset.

### Block 4: `runbook`
- **Stub & Boilerplate Detection:** Flag (`FAIL`) if `context`, `triage`, or `response` still contain the default `graft new rule` placeholder text (`"Context and background regarding this detection."`, `"1. Verify principal user and host."`).
- **Operational Specificity:**
  - Does `runbook.context` explain the threat model and realistic false-positive scenarios?
  - Does `runbook.triage` reference the actual entities, fields, or outcome variables produced by `logic`?
  - Does `runbook.response` provide concrete, graduated containment and remediation steps specific to the affected platform?

### Block 5: `tests` *(Custom Rules)*
- **Coverage:** Does `tests` include at least one positive vector (`id: "match_*"`, `expect: 1`) and one negative vector (`id: "ignore_*"`, `expect: 0`)?
- **Predicate Verification:**
  - Trace every event in the positive vector against `logic`: do all field paths, values, regexes, join keys, and timestamps within the `match:` window actually satisfy `condition:`?
  - Trace the negative vector against `logic`: does it falsify a specific condition while remaining realistic?
  - Flag (`FAIL`) if `tests` still contains the default `test_basic_detection` (`USER_LOGIN`) stub after `logic` has been customized.

---

## 3. Output Report Format

Present your review in this concise structure for each rule:

```markdown
## Review Report: `<rule_name>` (`<rule_path>`)

- **Linter (`graft lint`):** `PASS` | `FAIL`
- **Overall Verdict:** `READY` | `NEEDS REVISION`

| Block | Check | Status | Finding & Actionable Fix |
| :--- | :--- | :---: | :--- |
| `metadata` | Naming, MITRE, Tags, Refs | `PASS` / `WARN` / `FAIL` | Concrete explanation |
| `logic` | Query semantics & hygiene | `PASS` / `WARN` / `FAIL` | Concrete explanation |
| `deployment` | Rollout posture | `PASS` / `WARN` / `FAIL` | Concrete explanation |
| `runbook` | Context, Triage, Response | `PASS` / `WARN` / `FAIL` | Concrete explanation |
| `tests` | Positive & negative vectors | `PASS` / `WARN` / `FAIL` | Concrete explanation |

### Suggested Fixes
(Include exact YAML or query snippets for any `WARN` or `FAIL` items)
```

Do **not** edit the rule file unless the analyst explicitly instructs you to apply the suggested fixes.

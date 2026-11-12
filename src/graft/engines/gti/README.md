# Google Threat Intelligence (`gti`) Engine Adapter

Driven engine adapter connecting Graft's hexagonal detection core to the **Google Threat Intelligence (VirusTotal v3 Livehunt & Retrohunt)** REST API (`/api/v3/intelligence/...`).

---

## Package Layout

- [`engine.yaml`](engine.yaml) — Engine manifest declaring capabilities (`custom_rules: true`, `syntax_verification: true`, `replay_testing: true`, `datasets: false`, `managed_rules: false`) and environment variables.
- [`.env.example`](.env.example) — Engine-scoped environment variable template (`GRAFT_GTI_*`).
- [`adapter.py`](adapter.py) — [`GTIAdapter`](adapter.py), the primary `EngineAdapter` composite implementation, default YARA rule logic and deployment config provider, dataset cross-reference rejection check (`datasets: false`), and synthesized YARA content comparator.
- [`config.py`](config.py) — [`GTIConfig`](config.py), resolving tiered (`staging` / `prod`) and single-tenant fallback GTI API keys, ruleset discovery scope (`GRAFT_GTI_FILTER`), and default notification email recipients.
- [`client.py`](client.py) — [`GTIClient`](client.py), `urllib.request` JSON:API REST client for VirusTotal / GTI v3 endpoints with exponential backoff and authenticated user ID caching.
- [`compiler.py`](compiler.py) — [`GTICompilerAdapter`](compiler.py), partitioning `$LOGIC_IMPORTS` (`import "vt"`, `import "pe"`) from `$LOGIC_BODY`, injecting Graft `meta:` attribution, losslessly deconstructing remote YARA rules, and verifying syntax via transient disabled Livehunt rulesets.
- [`deployer.py`](deployer.py) — [`GTIDeployerAdapter`](deployer.py), custom Livehunt ruleset (`/api/v3/intelligence/hunting_rulesets`) and Retrohunt job (`/api/v3/intelligence/retrohunt_jobs`) CRUD with owner-scoped discovery (`owner:self` default) and a hard read-only guard against modifying or deleting non-owned resources in shared GTI organizations.
- [`replay.py`](replay.py) — [`GTIReplayAdapter`](replay.py), dual-mode test harness supporting fast deterministic evaluation of synthetic `vt.*` / `strings:` event vectors and asynchronous GTI Retrohunt jobs (`/api/v3/intelligence/retrohunt_jobs`).
- [`schemas/`](schemas/) — Co-located JSON Schema (`custom.schema.json`) defining GTI-native `deployment` parameters (`type`, `subtype`, `enabled`, `daily_limit`, `corpus`, `start_time`, `end_time`, `notification_emails`).
- [`docs/`](docs/) — Co-located Google Threat Intelligence engine setup and operational guide.

---

## Authoritative Documentation

For complete setup instructions, shared-organization scoping, native YARA-X `import "vt"` authoring, Livehunt (`type: "livehunt"`, `subtype`) and Retrohunt (`type: "retrohunt"`, `corpus`, `start_time`, `end_time`) deployment configuration, and replay testing, see the co-located engine documentation:

- **[Google Threat Intelligence Engine Setup & Operations Guide (`docs/README.md`)](docs/README.md)**

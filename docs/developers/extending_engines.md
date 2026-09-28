# Extending Graft: Building New Engine Adapters

> **Step-by-Step Tutorial for Implementing a SIEM or Analytics Engine Adapter**  
> **Target Audience:** Engine Developers, Integration Engineers, Contributors  
> **Reference Example:** Building a Microsoft Sentinel (`sentinel`) Adapter

---

## 1. Overview of the Engine Package Structure

Graft's hexagonal architecture ensures that each engine exists as a completely self-contained, encapsulated package under `src/graft/engines/<engine>/`. An engine owns its manifest, adapter, configuration, compiler, deployer, schemas, and in-tree tests.

```text
src/graft/engines/sentinel/
├── __init__.py           # Package entrypoint
├── engine.yaml           # Engine manifest discovered by EngineRegistry
├── adapter.py            # Primary EngineAdapter protocol implementation
├── config.py             # Credentials and environment coordinate resolution
├── compiler.py           # Syntax verification implementing RuleCompilerPort
├── deployer.py           # Custom rule CRUD implementing RuleDeployerPort
├── schemas/
│   └── rule.schema.json      # Engine-specific rule schema for graft lint
└── README.md                 # Engine documentation
```

Engine tests live in `tests/engines/<engine>/`:
```text
tests/engines/sentinel/
├── __init__.py
├── test_compiler.py          # Compiler unit tests
└── test_adapter.py           # Adapter contract tests
```

Additionally, Graft maintains an engine-namespaced rule catalog:
```text
rulesets/sentinel/
└── custom/
    └── sentinel_example_rule.yaml  # Initial scaffolded rule envelope
```

---

## 2. Step 1: Scaffold the Engine via CLI

Graft provides an automated scaffolding command to generate the complete package boilerplate:

```bash
uv run graft new engine sentinel
```

This command:
1. Validates the engine identifier slug (`^[a-z0-9_]+$`).
2. Creates `src/graft/engines/sentinel/` and all boilerplate files.
3. Creates `rulesets/sentinel/custom/` with an example detection envelope.
4. Generates initial in-tree test files.

---

## 3. Step 2: Configure the Manifest (`engine.yaml`)

Edit `src/graft/engines/sentinel/engine.yaml` to declare metadata, supported capabilities, environments, and environment variables:

```yaml
name: sentinel
display_name: Microsoft Sentinel
description: Microsoft Sentinel Detection Engine Adapter
adapter_class: graft.engines.sentinel.adapter:SentinelAdapter

capabilities:
  custom_rules: true
  syntax_verification: true
  managed_rules: false
  replay_testing: false

environments:
  - staging
  - production

env_vars:
  required:
    - GRAFT_SENTINEL_SUBSCRIPTION_ID
    - GRAFT_SENTINEL_RESOURCE_GROUP
    - GRAFT_SENTINEL_WORKSPACE_NAME
  optional:
    - GRAFT_SENTINEL_AUTH_TOKEN
```

> [!TIP]
> The manifest is validated against `src/graft/core/schemas/engine_manifest.schema.json`. Capabilities declared here dictate which CLI commands Core registers for this engine.

---

## 4. Step 3: Define Engine Rule Schema (`schemas/rule.schema.json`)

Custom detection envelopes use a 5-block structure: `metadata`, `logic`, `deployment`, `runbook`, `tests`. Each engine co-locates a Draft 2020-12 JSON schema that extends `base_rule.schema.json` via `allOf`.

Edit `src/graft/engines/sentinel/schemas/rule.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "sentinel_rule.schema.json",
  "title": "Sentinel Custom Rule Envelope Schema",
  "type": "object",
  "allOf": [
    {
      "$ref": "base_rule.schema.json"
    },
    {
      "type": "object",
      "properties": {
        "deployment": {
          "type": "object",
          "required": ["enabled", "alerting"],
          "properties": {
            "enabled": { "type": "boolean" },
            "alerting": { "type": "boolean" },
            "run_frequency": {
              "type": "string",
              "enum": ["unspecified", "live", "hourly", "daily"]
            }
          },
          "additionalProperties": false
        }
      }
    }
  ]
}
```

When an analyst runs `graft lint`, Graft automatically discovers `schemas/rule.schema.json` and validates all `rulesets/sentinel/custom/*.yaml` envelopes against it.

---

## 5. Step 4: Configuration & Authentication (`config.py`)

Graft follows a strict **stdlib-first** policy. Use `os.environ` and `dataclasses`:

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Self


class SentinelConfigError(Exception):
    pass


@dataclass(frozen=True)
class SentinelConfig:
    subscription_id: str
    resource_group: str
    workspace_name: str
    auth_token: str | None = None

    @classmethod
    def from_env(cls, env: str = "production") -> Self:
        prefix = f"GRAFT_SENTINEL_{env.upper()}"
        sub_id = os.environ.get(f"{prefix}_SUBSCRIPTION_ID") or os.environ.get(
            "GRAFT_SENTINEL_SUBSCRIPTION_ID"
        )
        res_group = os.environ.get(f"{prefix}_RESOURCE_GROUP") or os.environ.get(
            "GRAFT_SENTINEL_RESOURCE_GROUP"
        )
        ws_name = os.environ.get(f"{prefix}_WORKSPACE_NAME") or os.environ.get(
            "GRAFT_SENTINEL_WORKSPACE_NAME"
        )

        if not sub_id or not res_group or not ws_name:
            raise SentinelConfigError(
                f"Missing required Sentinel coordinates for environment '{env}'"
            )

        token = os.environ.get(f"{prefix}_AUTH_TOKEN") or os.environ.get(
            "GRAFT_SENTINEL_AUTH_TOKEN"
        )
        return cls(
            subscription_id=sub_id,
            resource_group=res_group,
            workspace_name=ws_name,
            auth_token=token,
        )
```

---

## 6. Step 5: Implement the Compiler (`compiler.py`)

The compiler implements [`RuleCompilerPort`](../../src/graft/core/ports/compiler.py):

```python
from __future__ import annotations

import json
import urllib.error
import urllib.request

from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.engines.sentinel.config import SentinelConfig


class SentinelCompilerAdapter(RuleCompilerPort):
    def __init__(self, config: SentinelConfig | None = None) -> None:
        self.config = config

    def verify_syntax(self, rule_text: str) -> CompilationResult:
        if not self.config or not self.config.auth_token:
            if "where" not in rule_text and "summarize" not in rule_text:
                return CompilationResult(
                    success=False,
                    diagnostics=(
                        CompilationDiagnostic(line=1, message="KQL query appears incomplete"),
                    ),
                )
            return CompilationResult(success=True)

        url = (
            f"https://management.azure.com/subscriptions/{self.config.subscription_id}"
            f"/resourceGroups/{self.config.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.config.workspace_name}"
            f"/api/query/validate?api-version=2020-08-01"
        )
        req = urllib.request.Request(
            url,
            data=json.dumps({"query": rule_text}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("valid", False):
                    return CompilationResult(success=True)
                return CompilationResult(
                    success=False,
                    diagnostics=(
                        CompilationDiagnostic(line=1, message=data.get("error", "Syntax error")),
                    ),
                )
        except urllib.error.HTTPError as exc:
            return CompilationResult(
                success=False,
                diagnostics=(CompilationDiagnostic(line=1, message=f"API error: {exc}"),),
            )

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        return self.verify_syntax(rule.logic)
```

---

## 7. Step 6: Implement the Deployer (`deployer.py`)

The deployer implements [`RuleDeployerPort`](../../src/graft/core/ports/deployer.py):

```python
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata
from graft.core.ports.deployer import RuleDeployerPort
from graft.engines.sentinel.config import SentinelConfig


class SentinelDeployerAdapter(RuleDeployerPort):
    def __init__(self, config: SentinelConfig) -> None:
        self.config = config

    def list_rules(self) -> tuple[RuleEnvelope, ...]:
        url = (
            f"https://management.azure.com/subscriptions/{self.config.subscription_id}"
            f"/resourceGroups/{self.config.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.config.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01"
        )
        return ()

    def create_rule(self, rule: RuleEnvelope) -> str:
        return rule.metadata.id

    def update_rule(self, rule: RuleEnvelope) -> None:
        pass

    def delete_rule(self, rule_id: str) -> None:
        pass

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        pass
```

---

## 8. Step 7: Assemble the Composite Adapter (`adapter.py`)

The composite adapter implements [`EngineAdapter`](../../src/graft/core/ports/engine.py). Inheriting from `EngineAdapter` provides default implementations for `resolve_deployment_status`, `are_rules_equal`, `deconstruct_rule`, `load_managed_manifest`, and `dump_managed_manifest`, which your adapter can override when needed (for example, `SecOpsAdapter` overrides `are_rules_equal` and `deconstruct_rule` to inject/extract YAML `metadata` and `runbook` fields into the YARA-L `meta:` block):

```python
from __future__ import annotations

from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.ports.deployer import RuleDeployerPort
from graft.core.ports.engine import EngineAdapter
from graft.core.ports.managed import ManagedEnginePort
from graft.core.ports.replay import ReplayHarnessPort
from graft.engines.sentinel.compiler import SentinelCompilerAdapter
from graft.engines.sentinel.config import SentinelConfig
from graft.engines.sentinel.deployer import SentinelDeployerAdapter


class SentinelAdapter(EngineAdapter):
    def __init__(self, env: str = "production") -> None:
        self.env = env
        try:
            self._config = SentinelConfig.from_env(env=env)
        except Exception:
            self._config = None

        self._compiler = SentinelCompilerAdapter(config=self._config)
        self._deployer = SentinelDeployerAdapter(config=self._config) if self._config else None

    def get_compiler(self) -> RuleCompilerPort | None:
        return self._compiler

    def get_deployer(self) -> RuleDeployerPort | None:
        return self._deployer

    def get_managed(self) -> ManagedEnginePort | None:
        return None

    def get_replay(self) -> ReplayHarnessPort | None:
        return None

    def resolve_deployment_status(self, rule: RuleEnvelope) -> str:
        if not rule.deployment.enabled:
            return "disabled"
        return "enabled" if rule.deployment.alerting else "silent"
```

---

## 9. Step 8: Write In-Tree Tests

In Graft, engine tests live in `tests/engines/<engine>/`. Root `tests/unit/core/` is reserved strictly for engine-agnostic core logic and CLI routing.

Create `tests/engines/sentinel/test_sentinel_adapter.py`:

```python
from graft.core.ports.engine import EngineAdapter
from graft.engines.sentinel.adapter import SentinelAdapter


def test_sentinel_adapter_conforms_to_protocol() -> None:
    adapter = SentinelAdapter(env="production")
    assert isinstance(adapter, EngineAdapter)
    assert adapter.get_compiler() is not None
    assert adapter.get_managed() is None
    assert adapter.get_replay() is None
```

Run pytest to verify discovery and execution:

```bash
uv run pytest tests/engines/sentinel
```

---

## 10. Summary Verification Checklist

Before submitting an engine PR:
- [ ] Manifest `engine.yaml` is valid according to `src/graft/core/schemas/engine_manifest.schema.json`.
- [ ] Rule schema `schemas/rule.schema.json` validates example rules.
- [ ] All HTTP interactions use `urllib.request` (zero third-party dependencies).
- [ ] Adapter passes `isinstance(adapter, EngineAdapter)` protocol checks.
- [ ] Engine tests achieve 100% pass rate in `uv run pytest tests/engines/<engine>`.
- [ ] Code passes strict static quality gates: `uv run ruff check .`, `uv run ruff format --check .`, and `uv run mypy --strict src tests`.

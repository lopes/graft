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

## 4. Step 3: Define Engine Logic Schema (`schemas/rule_logic.schema.json`)

Custom detection envelopes use a 5-block structure: `metadata`, `logic`, `deployment`, `runbook`, `tests`. The `logic:` block contains engine-specific queries.

Create `src/graft/engines/sentinel/schemas/rule_logic.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["query", "query_frequency", "query_period"],
  "properties": {
    "query": {
      "type": "string",
      "minLength": 5,
      "description": "Kusto Query Language (KQL) detection expression"
    },
    "query_frequency": {
      "type": "string",
      "pattern": "^PT[0-9]+[MH]$",
      "description": "ISO 8601 duration (e.g., PT5M, PT1H)"
    },
    "query_period": {
      "type": "string",
      "pattern": "^PT[0-9]+[MH]$",
      "description": "ISO 8601 lookback period"
    }
  },
  "additionalProperties": false
}
```

When an analyst runs `graft lint`, Graft automatically discovers this schema and validates all `rulesets/sentinel/custom/*.yaml` logic blocks against it.

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

The compiler implements [`RuleCompilerPort`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/core/ports/compiler.py):

```python
from __future__ import annotations

import json
import urllib.error
import urllib.request

from graft.core.models.compiler import CompilationError, CompilationResult
from graft.core.ports.compiler import RuleCompilerPort
from graft.engines.sentinel.config import SentinelConfig


class SentinelCompilerAdapter(RuleCompilerPort):
    def __init__(self, config: SentinelConfig | None = None) -> None:
        self.config = config

    def verify_syntax(self, rule_text: str) -> CompilationResult:
        """Verifies KQL query syntax against the Azure Sentinel query parser."""
        if not self.config or not self.config.auth_token:
            # Fallback to local basic syntax verification if credentials are absent
            if "where" not in rule_text and "summarize" not in rule_text:
                return CompilationResult(
                    success=False,
                    errors=(CompilationError(line=1, message="KQL query appears incomplete"),),
                )
            return CompilationResult(success=True)

        # Call remote API using urllib.request (stdlib only)
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
                    errors=(CompilationError(line=1, message=data.get("error", "Syntax error")),),
                )
        except urllib.error.HTTPError as exc:
            return CompilationResult(
                success=False,
                errors=(CompilationError(line=1, message=f"API error: {exc}"),),
            )

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        """Verifies rule envelope syntax."""
        return self.verify_syntax(rule.logic)
```

---

## 7. Step 6: Implement the Deployer (`deployer.py`)

The deployer implements [`RuleDeployerPort`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/core/ports/deployer.py):

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
        """Fetches all alert rules from Azure Sentinel and transforms them into RuleEnvelopes."""
        url = (
            f"https://management.azure.com/subscriptions/{self.config.subscription_id}"
            f"/resourceGroups/{self.config.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.config.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01"
        )
        # Fetch, parse JSON, and construct RuleEnvelope dataclasses
        return ()

    def create_rule(self, rule: RuleEnvelope) -> str:
        """Translates RuleEnvelope to Azure ScheduledAlertRule payload and issues PUT request."""
        rule_id = rule.metadata.id
        # PUT alertRules/{rule_id}
        return rule_id

    def update_rule(self, rule: RuleEnvelope) -> None:
        """Updates an existing scheduled alert rule in-place."""
        # PUT alertRules/{rule.metadata.id}
        pass

    def delete_rule(self, rule_id: str) -> None:
        """Deletes an alert rule."""
        # DELETE alertRules/{rule_id}
        pass

    def set_rule_state(self, rule_id: str, enabled: bool, alerting: bool) -> None:
        """Updates rule enabled/alerting state toggles."""
        # PATCH alertRules/{rule_id}
        pass
```

---

## 8. Step 7: Assemble the Composite Adapter (`adapter.py`)

The composite adapter implements [`EngineAdapter`](file:///usr/local/google/home/joelopes/Projects/graft/src/graft/core/ports/engine.py):

```python
from __future__ import annotations

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
        # Sentinel adapter does not support managed curated content in this phase
        return None

    def get_replay(self) -> ReplayHarnessPort | None:
        # Sentinel adapter does not support synthetic replay in this phase
        return None

    def resolve_deployment_status(self, rule: RuleEnvelope) -> str:
        """Translates engine deployment configuration to enabled | silent | disabled."""
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
- [ ] Logic schema `schemas/rule_logic.schema.json` validates example rules.
- [ ] All HTTP interactions use `urllib.request` (zero third-party dependencies).
- [ ] Adapter passes `isinstance(adapter, EngineAdapter)` protocol checks.
- [ ] Engine tests achieve 100% pass rate in `uv run pytest tests/engines/<engine>`.
- [ ] Code passes strict static quality gates: `uv run ruff check .`, `uv run ruff format --check .`, and `uv run mypy --strict src tests`.

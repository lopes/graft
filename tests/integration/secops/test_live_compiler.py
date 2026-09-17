import os

import pytest

from graft.adapters.secops.client import SecOpsClient
from graft.adapters.secops.compiler import SecOpsCompilerAdapter
from graft.adapters.secops.config import SecOpsConfig


@pytest.mark.integration
def test_live_verify_rule_text_staging() -> None:
    required_keys = [
        "GRAFT_STAGING_PROJECT",
        "GRAFT_STAGING_LOCATION",
        "GRAFT_STAGING_INSTANCE_ID",
    ]
    missing = [k for k in required_keys if k not in os.environ]
    if missing:
        pytest.skip(f"Staging credentials not in environment: {', '.join(missing)}")

    config = SecOpsConfig.from_env("staging")
    client = SecOpsClient(config=config)
    compiler = SecOpsCompilerAdapter(client=client)

    sample_yaral = """rule graft_integration_smoke_test {
  meta:
    description = "Smoke test rule for Graft CI/CD verifyRuleText"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
  condition:
    $e
}"""
    result = compiler.verify_syntax(sample_yaral)
    assert result.success is True
    assert result.diagnostics == ()

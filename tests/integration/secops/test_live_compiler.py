import pytest

from graft.core.env import load_env_file
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.compiler import SecOpsCompilerAdapter
from graft.engines.secops.config import SecOpsConfig


@pytest.mark.integration
def test_live_verify_rule_text_staging() -> None:
    load_env_file()
    try:
        config = SecOpsConfig.from_env("staging")
    except KeyError as exc:
        pytest.skip(f"Staging credentials not in environment: {exc}")
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

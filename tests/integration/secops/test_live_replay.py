import pytest

from graft.core.env import load_env_file
from graft.core.loader import load_rule_from_yaml
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.config import SecOpsConfig
from graft.engines.secops.replay import SecOpsReplayAdapter


@pytest.mark.integration
@pytest.mark.replay
def test_live_replay_staging() -> None:
    load_env_file()
    try:
        config = SecOpsConfig.from_env("staging")
    except KeyError as exc:
        pytest.skip(f"Staging credentials not in environment: {exc}")

    client = SecOpsClient(config=config)
    adapter = SecOpsReplayAdapter(client=client, config=config)

    rule = load_rule_from_yaml(
        "rulesets/secops/custom/gcp_service_account_key_created.yaml",
        schema_name="secops_custom",
    )
    assert len(rule.tests) >= 1

    result = adapter.run_test_vector(rule, rule.tests[0])
    assert result.passed is True

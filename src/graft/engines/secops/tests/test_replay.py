from unittest.mock import MagicMock

from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestEvent,
    TestVector,
)
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.config import SecOpsConfig
from graft.engines.secops.replay import SecOpsReplayAdapter


def _build_test_envelope(name: str, expect: int = 1) -> RuleEnvelope:
    return RuleEnvelope(
        metadata=RuleMetadata(
            id="test-rule-id",
            name=name,
            description="Test rule description",
            status="testing",
        ),
        logic="""rule test_rule {
  meta:
    author = "Graft"
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
}""",
        deployment=BaseDeploymentConfig(enabled=True, alerting=False, run_frequency="live"),
        runbook=Runbook(),
        tests=(
            TestVector(
                id="test_vector_1",
                description="Test single login event",
                expect=expect,
                events=(
                    TestEvent(
                        timestamp="2026-09-17T12:00:00Z",
                        payload={"metadata": {"event_type": "USER_LOGIN"}},
                    ),
                ),
            ),
        ),
    )


def test_secops_replay_run_vector_success() -> None:
    mock_client = MagicMock(spec=SecOpsClient)
    # 1. udmIngest
    # 2. create_rule -> returns {"name": "rules/created-test-rule-id"}
    # 3. set_rule_state
    # 4. run -> returns {"detections": [{"id": "det-1"}]}
    # 5. delete_rule
    mock_client.request.side_effect = [
        {"success": True},  # udmIngest
        {"name": "rules/quarantined-rule-123"},  # create_rule
        {},  # set_rule_state
        {"detections": [{"id": "alert-1"}]},  # run
        {},  # delete_rule
    ]

    adapter = SecOpsReplayAdapter(client=mock_client)
    envelope = _build_test_envelope("test_rule", expect=1)
    result = adapter.run_test_vector(envelope, envelope.tests[0])

    assert result.passed is True
    assert result.matched_events_count == 1
    assert result.test_id == "test_vector_1"

    # Verify cleanup was called
    mock_client.request.assert_any_call("DELETE", "rules/quarantined-rule-123")


def test_secops_replay_run_vector_mismatch_fails() -> None:
    mock_client = MagicMock(spec=SecOpsClient)
    mock_client.request.side_effect = [
        {"success": True},  # udmIngest
        {"name": "rules/quarantined-rule-456"},  # create_rule
        {},  # set_rule_state
        {"detections": []},  # run (0 detections, expected 1)
        {},  # delete_rule
    ]

    adapter = SecOpsReplayAdapter(client=mock_client)
    envelope = _build_test_envelope("test_rule", expect=1)
    result = adapter.run_test_vector(envelope, envelope.tests[0])

    assert result.passed is False
    assert result.matched_events_count == 0
    assert "expected 1" in result.message.lower()

    # Verify cleanup was called even on assertion mismatch
    mock_client.request.assert_any_call("DELETE", "rules/quarantined-rule-456")


def test_secops_replay_guaranteed_cleanup_on_evaluation_error() -> None:
    mock_client = MagicMock(spec=SecOpsClient)
    mock_client.request.side_effect = [
        {"success": True},  # udmIngest
        {"name": "rules/quarantined-rule-789"},  # create_rule
        {},  # set_rule_state
        RuntimeError("Evaluation API internal error"),  # run throws exception
        {},  # delete_rule
    ]

    adapter = SecOpsReplayAdapter(client=mock_client)
    envelope = _build_test_envelope("test_rule", expect=1)
    result = adapter.run_test_vector(envelope, envelope.tests[0])

    assert result.passed is False
    assert "Evaluation API internal error" in result.message

    # Verify cleanup was still invoked in finally: block
    mock_client.request.assert_any_call("DELETE", "rules/quarantined-rule-789")


def test_secops_replay_is_available() -> None:
    valid_config = SecOpsConfig(project="my-proj", location="us", instance_id="my-inst")
    adapter_valid = SecOpsReplayAdapter(client=MagicMock(), config=valid_config)
    assert adapter_valid.is_available() is True

    adapter_none = SecOpsReplayAdapter(client=MagicMock(), config=None)
    assert adapter_none.is_available() is False

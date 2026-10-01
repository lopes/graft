from unittest.mock import MagicMock

import pytest

from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.compiler import (
    SecOpsCompilerAdapter,
    deconstruct_yaral_rule,
    synthesize_yaral_rule,
)


@pytest.fixture
def mock_client() -> MagicMock:
    return MagicMock(spec=SecOpsClient)


@pytest.fixture
def sample_rule() -> RuleEnvelope:
    metadata = RuleMetadata(
        id="a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
        name="test_network_beaconing",
        description="Detects beaconing to C2",
        owners=("Detection Team",),
        mitre={"command-and-control": ("T1071.001",)},
    )
    logic = """events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.target.ip = "198.51.100.1"

condition:
  $e"""
    runbook = Runbook(
        context="Sample context",
        triage="Sample triage",
        response="Sample response",
    )
    deployment = BaseDeploymentConfig(enabled=True, alerting=True)
    return RuleEnvelope(
        metadata=metadata,
        logic=logic,
        deployment=deployment,
        runbook=runbook,
        tests=(),
    )


def test_synthesize_yaral_rule(sample_rule: RuleEnvelope) -> None:
    rule_text, header_offset = synthesize_yaral_rule(sample_rule)

    assert "rule test_network_beaconing {" in rule_text
    assert 'id = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"' in rule_text
    assert 'description = "Detects beaconing to C2"' in rule_text
    # Strict check: only id, description in meta:
    assert "author" not in rule_text
    assert "owner" not in rule_text
    assert "severity" not in rule_text
    assert "  events:" in rule_text
    assert '    $e.metadata.event_type = "NETWORK_CONNECTION"' in rule_text
    assert "  condition:" in rule_text
    assert "    $e" in rule_text
    assert rule_text.strip().endswith("}")

    lines = rule_text.splitlines()
    assert lines[header_offset] == "  events:"
    assert lines[header_offset + 1] == '    $e.metadata.event_type = "NETWORK_CONNECTION"'


def test_verify_syntax_success(mock_client: MagicMock) -> None:
    mock_client.request.return_value = {"success": True}

    adapter = SecOpsCompilerAdapter(client=mock_client)
    result = adapter.verify_syntax("rule test { condition: true }")

    assert isinstance(result, CompilationResult)
    assert result.success is True
    assert result.diagnostics == ()
    mock_client.request.assert_called_once_with(
        "POST",
        ":verifyRuleText",
        body={"ruleText": "rule test { condition: true }"},
    )


def test_verify_syntax_raw_logic_synthesizes_wrapper(mock_client: MagicMock) -> None:
    mock_client.request.return_value = {"success": True}

    adapter = SecOpsCompilerAdapter(client=mock_client)
    raw_logic = 'events:\n  $e.metadata.event_type = "USER_LOGIN"\ncondition:\n  $e'
    result = adapter.verify_syntax(raw_logic)

    assert result.success is True
    # Verify request payload contains synthetic rule header and closing brace
    called_body = mock_client.request.call_args[1]["body"]
    rule_text = called_body["ruleText"]
    assert "rule verify_syntax_rule {" in rule_text
    assert "  events:" in rule_text
    assert '    $e.metadata.event_type = "USER_LOGIN"' in rule_text
    assert rule_text.strip().endswith("}")


def test_verify_syntax_compilation_error(mock_client: MagicMock) -> None:
    mock_client.request.return_value = {
        "success": False,
        "compilationDiagnostics": [
            {
                "message": "syntax error: unexpected token",
                "startLine": 10,
                "startColumn": 4,
                "severity": "ERROR",
            }
        ],
    }

    adapter = SecOpsCompilerAdapter(client=mock_client)
    result = adapter.verify_syntax("rule broken { ... }")

    assert result.success is False
    assert len(result.diagnostics) == 1
    diag = result.diagnostics[0]
    assert isinstance(diag, CompilationDiagnostic)
    assert diag.line == 10
    assert diag.column == 4
    assert diag.message == "syntax error: unexpected token"
    assert diag.severity == "ERROR"


def test_verify_rule_envelope_line_offset_translation(
    mock_client: MagicMock, sample_rule: RuleEnvelope
) -> None:
    # Synthesized rule has header_offset lines before logic starts.
    # Suppose Chronicle reports an error at line (header_offset + 3).
    # Then the relative line in sample_rule.logic is line 3.
    _, header_offset = synthesize_yaral_rule(sample_rule)
    error_line_in_synthesized = header_offset + 3

    mock_client.request.return_value = {
        "success": False,
        "compilationDiagnostics": [
            {
                "message": "undefined variable $x",
                "startLine": error_line_in_synthesized,
                "startColumn": 2,
                "severity": "ERROR",
            }
        ],
    }

    adapter = SecOpsCompilerAdapter(client=mock_client)
    result = adapter.verify_rule(sample_rule)

    assert result.success is False
    assert len(result.diagnostics) == 1
    diag = result.diagnostics[0]
    assert diag.line == 3  # Translated relative to logic block!
    assert diag.column == 2
    assert diag.message == "undefined variable $x"
    assert "synthesized_rule_text" in result.raw_response
    assert result.raw_response["header_offset"] == header_offset


def test_secops_rule_content_matches(sample_rule: RuleEnvelope) -> None:
    import dataclasses

    from graft.engines.secops.adapter import secops_rule_content_matches

    # Direct identical logic
    assert secops_rule_content_matches(sample_rule, sample_rule) is True

    # Remote rule with synthesized text
    synth_text, _ = synthesize_yaral_rule(sample_rule)
    remote_synth = dataclasses.replace(sample_rule, logic=synth_text)
    assert secops_rule_content_matches(sample_rule, remote_synth) is True

    # Remote rule with synthesized text with mismatched meta.id is detected as drift
    remote_rule_id = "ru_remote_999"
    remote_with_id = dataclasses.replace(
        sample_rule,
        metadata=dataclasses.replace(sample_rule.metadata, id=remote_rule_id),
    )
    synth_text_remote_id, _ = synthesize_yaral_rule(remote_with_id)
    remote_synth_id = dataclasses.replace(
        sample_rule,
        metadata=dataclasses.replace(sample_rule.metadata, id=remote_rule_id),
        logic=synth_text_remote_id,
    )
    assert secops_rule_content_matches(sample_rule, remote_synth_id) is False

    # Different logic should return False
    different = dataclasses.replace(sample_rule, logic="events:\n  $e\ncondition:\n  $e")
    assert secops_rule_content_matches(sample_rule, different) is False


def test_deconstruct_synthesized_yaral_rule(sample_rule: RuleEnvelope) -> None:
    synth_text, _ = synthesize_yaral_rule(sample_rule)
    metadata, logic = deconstruct_yaral_rule(
        synth_text,
        fallback_id=sample_rule.metadata.id,
        fallback_name=sample_rule.metadata.name,
    )

    assert metadata.id == sample_rule.metadata.id
    assert metadata.name == sample_rule.metadata.name
    assert metadata.description == sample_rule.metadata.description
    assert logic.strip() == sample_rule.logic.strip()


def test_deconstruct_custom_yaral_rule_with_ru_prefix() -> None:
    raw_yaral = """rule Suspicious_Login_Rule {
  meta:
    author = "SecOps Team"
    description = "Detects unusual login behavior"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
}"""
    metadata, logic = deconstruct_yaral_rule(
        raw_yaral,
        fallback_id="ru_b1d72370-5fa3-4cb8-a579-22a468d6f101",
        fallback_name="Suspicious Login Rule",
    )

    assert metadata.id == "b1d72370-5fa3-4cb8-a579-22a468d6f101"
    assert metadata.name == "suspicious_login_rule"
    assert metadata.description == "Detects unusual login behavior"
    assert metadata.owners == ()
    assert "events:" in logic
    assert "condition:" in logic
    assert "meta:" not in logic
    assert not logic.startswith("rule ")


def test_deconstruct_raw_logic_without_rule_block() -> None:
    raw_logic = """events:
  $e.metadata.event_type = "USER_LOGIN"
condition:
  $e"""
    metadata, logic = deconstruct_yaral_rule(
        raw_logic,
        fallback_id="ru_non_uuid_123",
        fallback_name="Raw User Login Rule",
    )

    import uuid

    # Deterministic UUID generated from non-UUID fallback
    expected_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "ru_non_uuid_123"))
    assert metadata.id == expected_uuid
    assert metadata.name == "raw_user_login_rule"
    assert logic.strip() == raw_logic.strip()


def test_deconstruct_indented_yaral_rule() -> None:
    indented_text = """rule sample {
  meta:
    id = "b1d72370-5fa3-4cb8-a579-22a468d6f101"
    description = "test"
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
}"""
    metadata, logic = deconstruct_yaral_rule(indented_text)
    assert metadata.id == "b1d72370-5fa3-4cb8-a579-22a468d6f101"
    assert metadata.description == "test"
    assert logic == 'events:\n  $e.metadata.event_type = "USER_LOGIN"\ncondition:\n  $e'


def test_extract_meta_id() -> None:
    from graft.engines.secops.compiler import extract_meta_id

    # Normal double quotes
    text1 = (
        'rule foo {\n  meta:\n    id = "b1d72370-5fa3-4cb8-a579-22a468d6f101"\n  events:\n    $e\n}'
    )
    assert extract_meta_id(text1) == "b1d72370-5fa3-4cb8-a579-22a468d6f101"

    # Single quotes and extra spacing
    text2 = "rule foo {\n  meta:\n    id = 'my-custom-id' \n  events:\n    $e\n}"
    assert extract_meta_id(text2) == "my-custom-id"

    # No meta block
    text3 = "rule foo {\n  events:\n    $e\n}"
    assert extract_meta_id(text3) is None

    # Meta block without id
    text4 = 'rule foo {\n  meta:\n    author = "SecOps"\n  events:\n    $e\n}'
    assert extract_meta_id(text4) is None


def test_deconstruct_sanitizes_and_truncates_rule_slug() -> None:
    long_header_rule = (
        "rule __GCP__Cloud__Storage__Bucket__Public__Access__Granted"
        "__Via__IAM__Policy__Change__Extra__ {"
        "\n  events:\n    $e\n  condition:\n    $e\n}"
    )
    metadata, _ = deconstruct_yaral_rule(long_header_rule)
    assert len(metadata.name) <= 64
    assert not metadata.name.startswith("_")
    assert not metadata.name.endswith("_")
    assert "__" not in metadata.name

    index_rule = "rule __index__ {\n  events:\n    $e\n  condition:\n    $e\n}"
    index_meta, _ = deconstruct_yaral_rule(index_rule)
    assert index_meta.name == "index_rule"

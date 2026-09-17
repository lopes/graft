from unittest.mock import MagicMock

import pytest

from graft.adapters.secops.client import SecOpsClient
from graft.adapters.secops.compiler import SecOpsCompilerAdapter, synthesize_yaral_rule
from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook


@pytest.fixture
def mock_client() -> MagicMock:
    return MagicMock(spec=SecOpsClient)


@pytest.fixture
def sample_rule() -> RuleEnvelope:
    metadata = RuleMetadata(
        id="a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
        name="test_network_beaconing",
        description="Detects beaconing to C2",
        status="production",
        authors=("Detection Team",),
        mitre={"command_and_control": ("T1071.001",)},
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
    assert 'status = "production"' in rule_text
    # Strict check: only id, description, status in meta:
    assert "author" not in rule_text
    assert "severity" not in rule_text
    assert sample_rule.logic in rule_text
    assert rule_text.strip().endswith("}")

    lines = rule_text.splitlines()
    assert lines[header_offset] == "events:"


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

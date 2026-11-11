from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from typing import Any
from unittest.mock import patch

import pytest

from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)
from graft.engines.gti.client import GTIClient
from graft.engines.gti.compiler import (
    GTICompilerAdapter,
    deconstruct_yara_rule,
    resolve_gti_subtype,
    synthesize_yara_rule,
    validate_gti_dataset_references,
)
from graft.engines.gti.config import GTIConfig


def _sample_phishing_rule(
    logic: str | None = None,
    deployment: dict[str, Any] | None = None,
) -> RuleEnvelope:
    default_logic = """import "vt"

condition:
  vt.net.url.new_url and
  not (
    vt.net.domain.root == "example.com" or
    vt.net.domain.root == "example.org"
  ) and
  vt.net.url.path icontains "/auth/login"
"""
    dep_dict = (
        deployment
        if deployment is not None
        else {"type": "livehunt", "subtype": "url", "enabled": True, "daily_limit": 100}
    )
    return RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000001",
            name="sso_login_portal_impersonated",
            description="Detects brand phishing URLs outside corporate root domains",
            owners=("secops-team", "threat-intel"),
            mitre={"initial-access": ("T1566.002",)},
            tags=("gti", "phishing"),
            references=("https://attack.mitre.org/techniques/T1566/002/",),
        ),
        logic=logic if logic is not None else default_logic,
        deployment=BaseDeploymentConfig.from_dict(dep_dict),
        runbook=Runbook(
            context="Brand phishing URLs observed in GTI URL feed.",
            triage="1. Inspect URL path and domain registration.",
            response="1. Submit takedown and block domain.",
        ),
    )


def test_synthesize_yara_rule_partitions_imports_and_injects_meta() -> None:
    rule = _sample_phishing_rule()
    yara_text, header_offset = synthesize_yara_rule(rule)

    assert yara_text.startswith('import "vt"\n\nrule sso_login_portal_impersonated {\n')
    assert 'graft_id = "8f14e45f-ceea-467a-a124-000000000001"' in yara_text
    assert 'mitre_tactic = "initial-access"' in yara_text
    assert 'mitre_technique = "T1566.002"' in yara_text
    assert 'vt.net.domain.root == "example.com"' in yara_text
    assert header_offset > 0


def test_synthesize_and_deconstruct_yara_rule_lossless_roundtrip() -> None:
    logic = """import "pe"
import "vt"

strings:
  $a = "VirtualAllocEx" ascii

condition:
  vt.metadata.file_type == vt.FileType.PE_EXE and $a"""
    rule = _sample_phishing_rule(logic=logic)
    synthesized, _ = synthesize_yara_rule(rule)

    remote_envelope = RuleEnvelope(
        metadata=RuleMetadata(id="", name=rule.metadata.name, description=""),
        logic=synthesized,
        deployment=rule.deployment,
    )
    deconstructed = deconstruct_yara_rule(remote_envelope)

    assert deconstructed.metadata.id == rule.metadata.id
    assert deconstructed.metadata.name == rule.metadata.name
    assert deconstructed.metadata.description == rule.metadata.description
    assert deconstructed.metadata.owners == rule.metadata.owners
    assert deconstructed.metadata.mitre == rule.metadata.mitre
    assert deconstructed.logic.strip() == rule.logic.strip()


def test_resolve_gti_subtype_requires_explicit_subtype_without_guessing() -> None:
    for subtype in ("file", "url", "domain", "ip_address"):
        rule = _sample_phishing_rule(
            deployment={"type": "livehunt", "subtype": subtype, "enabled": True}
        )
        assert resolve_gti_subtype(rule) == subtype

    retro_rule = _sample_phishing_rule(
        deployment={"type": "retrohunt", "enabled": False, "corpus": "main"}
    )
    assert resolve_gti_subtype(retro_rule) == "file"

    missing_type = _sample_phishing_rule(deployment={"enabled": True})
    with pytest.raises(ValueError, match="deployment\\.type"):
        resolve_gti_subtype(missing_type)

    missing_subtype = _sample_phishing_rule(deployment={"type": "livehunt", "enabled": True})
    with pytest.raises(ValueError, match="deployment\\.subtype"):
        resolve_gti_subtype(missing_subtype)


def test_validate_gti_dataset_references_rejects_dataset_tokens() -> None:
    clean_rule = _sample_phishing_rule()
    validate_gti_dataset_references(clean_rule, local_dataset_names={"corporate_domains"})

    rule_with_dataset = _sample_phishing_rule(
        logic='import "vt"\ncondition:\n  vt.net.domain.root in (%corporate_domains.value)'
    )
    with pytest.raises(ValueError, match="does not support dataset lookup tables"):
        validate_gti_dataset_references(
            rule_with_dataset, local_dataset_names={"corporate_domains"}
        )


def test_compiler_verify_rule_transient_disabled_ruleset_and_cleanup() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    compiler = GTICompilerAdapter(client=client)
    rule = _sample_phishing_rule(logic='import "vt"\ncondition:\n  vt.net.url.new_url')

    calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        calls.append((method, path, payload))
        if method == "POST" and path == "/intelligence/hunting_rulesets":
            assert payload is not None
            attrs = payload["data"]["attributes"]
            assert attrs["enabled"] is False
            assert attrs["match_object_type"] == "url"
            return {"data": {"type": "hunting_ruleset", "id": "temp_verify_123"}}
        if method == "DELETE" and path == "/intelligence/hunting_rulesets/temp_verify_123":
            return {}
        raise AssertionError(f"Unexpected call: {method} {path}")

    with patch.object(client, "request", side_effect=fake_request):
        result = compiler.verify_rule(rule)

    assert result.success is True
    assert len(calls) == 2
    assert calls[0][0] == "POST"
    assert calls[1] == ("DELETE", "/intelligence/hunting_rulesets/temp_verify_123", None)


def test_compiler_verify_rule_maps_remote_line_offset_on_syntax_error() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    compiler = GTICompilerAdapter(client=client)
    rule = _sample_phishing_rule(logic='import "vt"\n\ncondition:\n  vt.net.url.invalid_field ==')
    _, offset = synthesize_yara_rule(rule)

    def fake_urlopen(req: Any, timeout: float = 30.0) -> Any:
        err_body = json.dumps(
            {
                "error": {
                    "code": "InvalidArgumentError",
                    "message": (
                        f"Invalid YARA rule: line {offset + 4}: "
                        "syntax error, unexpected end of file"
                    ),
                }
            }
        ).encode("utf-8")
        raise urllib.error.HTTPError(
            req.full_url, 400, "Bad Request", Message(), io.BytesIO(err_body)
        )

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = compiler.verify_rule(rule)

    assert result.success is False
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].line >= 1
    assert "syntax error" in result.diagnostics[0].message

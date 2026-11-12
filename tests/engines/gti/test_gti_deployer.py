from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
)
from graft.engines.gti.client import GTIApiError, GTIClient
from graft.engines.gti.compiler import synthesize_yara_rule
from graft.engines.gti.config import GTIConfig
from graft.engines.gti.deployer import GTIDeployerAdapter


def _build_rule() -> RuleEnvelope:
    return RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000001",
            name="suspicious_brand_phishing_url",
            description="Detects brand phishing URLs",
            owners=("secops-team",),
            mitre={"initial-access": ("T1566.002",)},
            tags=("web", "sso", "phishing"),
            references=("https://example.com",),
        ),
        logic='import "vt"\n\ncondition:\n  vt.net.url.new_url',
        deployment=BaseDeploymentConfig.from_dict(
            {
                "type": "livehunt",
                "subtype": "url",
                "enabled": True,
                "daily_limit": 200,
                "notification_emails": ["soc@example.com"],
            }
        ),
        runbook=Runbook(context="ctx", triage="tri", response="resp"),
    )


def test_deployer_list_rules_default_owner_self_and_skips_group_editable_colleague_rules() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    assert cfg.ruleset_filter == "owner:self"
    client = GTIClient(cfg, base_delay_seconds=0.0)
    deployer = GTIDeployerAdapter(client=client)
    rule = _build_rule()
    yara_text, _ = synthesize_yara_rule(rule)

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if path == f"/users/{cfg.api_key}":
            return {"data": {"type": "user", "id": "graft_bot_user"}}
        if path == "/users/graft_bot_user/hunting_rulesets":
            assert params is not None
            assert params.get("relationships") == "owner"
            return {
                "data": [
                    {
                        "type": "hunting_ruleset",
                        "id": "rs_owned_1",
                        "attributes": {
                            "name": rule.metadata.name,
                            "rules": yara_text,
                            "enabled": True,
                            "match_object_type": "url",
                            "limit": 200,
                            "notification_emails": ["soc@example.com"],
                            "tags": ["web", "sso", "phishing"],
                        },
                        "relationships": {
                            "owner": {"data": {"type": "user", "id": "graft_bot_user"}}
                        },
                    },
                    {
                        "type": "hunting_ruleset",
                        "id": "rs_colleague_group_editable",
                        "attributes": {
                            "name": "colleague_shared_rule",
                            "rules": yara_text,
                            "enabled": True,
                            "match_object_type": "url",
                            "limit": 100,
                            "notification_emails": [],
                            "tags": ["shared"],
                        },
                        "relationships": {
                            "owner": {"data": {"type": "user", "id": "colleague_alice"}}
                        },
                    },
                ],
                "meta": {},
            }
        if path == "/users/graft_bot_user/retrohunt_jobs":
            assert params is not None
            assert params.get("relationships") == "owner"
            return {"data": [], "meta": {}}
        raise AssertionError(f"Unexpected path: {path}")

    with patch.object(client, "request", side_effect=fake_request):
        rules = deployer.list_rules()

    assert len(rules) == 1
    assert rules[0].metadata.name == "suspicious_brand_phishing_url"
    assert rules[0].metadata.tags == ("web", "sso", "phishing")
    assert rules[0].deployment.to_dict() == {
        "type": "livehunt",
        "subtype": "url",
        "enabled": True,
        "daily_limit": 200,
        "notification_emails": ["soc@example.com"],
    }


def test_deployer_hard_read_only_guard_blocks_modifying_or_deleting_colleague_rulesets() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000", ruleset_filter="all")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    deployer = GTIDeployerAdapter(client=client)
    colleague_rule = _build_rule()
    yara_text, _ = synthesize_yara_rule(colleague_rule)

    mutating_calls: list[tuple[str, str]] = []

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if method in ("PATCH", "DELETE", "POST"):
            mutating_calls.append((method, path))
        if path.startswith("/users/"):
            return {"data": {"type": "user", "id": "me_user"}}
        if path == "/intelligence/hunting_rulesets":
            return {
                "data": [
                    {
                        "type": "hunting_ruleset",
                        "id": "rs_colleague_99",
                        "attributes": {
                            "name": colleague_rule.metadata.name,
                            "rules": yara_text,
                            "enabled": True,
                            "match_object_type": "url",
                            "limit": 100,
                            "notification_emails": [],
                        },
                        "relationships": {
                            "owner": {"data": {"type": "user", "id": "other_ce_colleague"}}
                        },
                    }
                ],
                "meta": {},
            }
        if path == "/intelligence/retrohunt_jobs":
            return {"data": [], "meta": {}}
        raise AssertionError(f"Unexpected request: {method} {path}")

    with patch.object(client, "request", side_effect=fake_request):
        pulled = deployer.list_rules()
        assert len(pulled) == 1

        with pytest.raises(GTIApiError, match="owned by another user"):
            deployer.update_rule(colleague_rule)

        with pytest.raises(GTIApiError, match="owned by another user"):
            deployer.delete_rule(colleague_rule.metadata.id)

        with pytest.raises(GTIApiError, match="owned by another user"):
            deployer.set_rule_state(colleague_rule.metadata.id, enabled=False, alerting=False)

    assert mutating_calls == []


def test_deployer_create_update_and_delete_owned_ruleset() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    deployer = GTIDeployerAdapter(client=client)
    rule = _build_rule()

    recorded: list[tuple[str, str, dict[str, Any] | None]] = []

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        recorded.append((method, path, payload))
        if path.startswith("/users/"):
            return {"data": {"type": "user", "id": "me_user"}}
        if method == "POST" and path == "/intelligence/hunting_rulesets":
            assert payload is not None
            assert payload["data"]["attributes"]["tags"] == ["web", "sso", "phishing"]
            return {
                "data": {
                    "type": "hunting_ruleset",
                    "id": "rs_created_1",
                    "relationships": {"owner": {"data": {"type": "user", "id": "me_user"}}},
                }
            }
        if method == "PATCH" and path == "/intelligence/hunting_rulesets/rs_created_1":
            return {"data": {"type": "hunting_ruleset", "id": "rs_created_1"}}
        if method == "DELETE" and path == "/intelligence/hunting_rulesets/rs_created_1":
            return {}
        raise AssertionError(f"Unexpected call: {method} {path}")

    with patch.object(client, "request", side_effect=fake_request):
        created_id = deployer.create_rule(rule)
        assert created_id == "rs_created_1"
        deployer.update_rule(rule)
        deployer.set_rule_state(rule.metadata.id, enabled=False, alerting=False)
        deployer.delete_rule(rule.metadata.id)

    methods = [m for m, p, _ in recorded if not p.startswith("/users/")]
    assert methods == ["POST", "PATCH", "PATCH", "DELETE"]


def test_deployer_retrohunt_job_lifecycle_and_dormant_check() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    deployer = GTIDeployerAdapter(client=client)

    dormant_retro = RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000050",
            name="lsass_minidump_credential_dumper_uploaded",
            description="Retrohunt rule for credential dumpers",
            owners=("Threat Intelligence",),
            mitre={"credential-access": ("T1003.001",)},
            tags=("windows", "pe", "lsass"),
            references=("https://example.com",),
        ),
        logic='import "pe"\ncondition:\n  filesize < 5000000',
        deployment=BaseDeploymentConfig.from_dict(
            {
                "type": "retrohunt",
                "enabled": False,
                "corpus": "main",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-03-31T23:59:59Z",
            }
        ),
        runbook=Runbook(context="ctx", triage="tri", response="resp"),
    )
    assert deployer.should_deploy_rule(dormant_retro) is False

    active_retro = RuleEnvelope(
        metadata=dormant_retro.metadata,
        logic=dormant_retro.logic,
        deployment=BaseDeploymentConfig.from_dict(
            {
                "type": "retrohunt",
                "enabled": True,
                "corpus": "goodware",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-02-01T00:00:00Z",
                "notification_emails": ["retro@example.com"],
            }
        ),
        runbook=dormant_retro.runbook,
    )
    assert deployer.should_deploy_rule(active_retro) is True
    yara_text, _ = synthesize_yara_rule(active_retro)

    recorded: list[tuple[str, str, dict[str, Any] | None]] = []

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        recorded.append((method, path, payload))
        if path == f"/users/{cfg.api_key}":
            return {"data": {"type": "user", "id": "me_user"}}
        if path == "/users/me_user/hunting_rulesets":
            return {"data": [], "meta": {}}
        if path == "/users/me_user/retrohunt_jobs" and method == "GET":
            return {
                "data": [
                    {
                        "type": "retrohunt_job",
                        "id": "rh_job_777",
                        "attributes": {
                            "rules": yara_text,
                            "status": "running",
                            "corpus": "goodware",
                            "time_range": {"start": 1767225600, "end": 1769904000},
                            "notification_email": "retro@example.com",
                        },
                        "relationships": {"owner": {"data": {"type": "user", "id": "me_user"}}},
                    }
                ],
                "meta": {},
            }
        if method == "POST" and path == "/intelligence/retrohunt_jobs":
            assert payload is not None
            attrs = payload["data"]["attributes"]
            assert attrs["corpus"] == "goodware"
            assert attrs["time_range"] == {"start": 1767225600, "end": 1769904000}
            assert attrs["notification_email"] == "retro@example.com"
            return {"data": {"type": "retrohunt_job", "id": "rh_job_777"}}
        raise AssertionError(f"Unexpected call: {method} {path}")

    with patch.object(client, "request", side_effect=fake_request):
        job_id = deployer.create_rule(active_retro)
        assert job_id == "rh_job_777"
        listed = deployer.list_rules()
        assert len(listed) == 1
        assert listed[0].deployment.get("type") == "retrohunt"
        assert listed[0].metadata.tags == ("windows", "pe", "lsass")
        assert deployer.are_deployments_equal(active_retro, listed[0]) is True

        # Updating a Retrohunt rule or disabling it must NEVER delete or abort existing jobs/results
        deployer.update_rule(dormant_retro)
        deployer.set_rule_state(active_retro.metadata.id, enabled=False, alerting=False)
        deployer.update_rule(active_retro)

    delete_or_abort_calls = [
        (m, p) for m, p, _ in recorded if m == "DELETE" or p.endswith("/abort")
    ]
    assert delete_or_abort_calls == []
    post_job_calls = [
        (m, p) for m, p, _ in recorded if m == "POST" and p == "/intelligence/retrohunt_jobs"
    ]
    assert len(post_job_calls) == 2

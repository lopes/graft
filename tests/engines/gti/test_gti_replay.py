from __future__ import annotations

from typing import Any
from unittest.mock import patch

from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestEvent,
    TestVector,
)
from graft.engines.gti.client import GTIClient
from graft.engines.gti.config import GTIConfig
from graft.engines.gti.replay import GTIReplayAdapter


def _build_phishing_rule_with_vectors() -> RuleEnvelope:
    logic = """import "vt"

condition:
  vt.net.url.new_url and
  not (
    vt.net.domain.root == "example.com" or
    vt.net.domain.root == "example.org" or
    vt.net.domain.raw == "login.sailpoint.example.com" or
    vt.net.domain.raw == "id.example.com"
  ) and
  (
    vt.net.url.path icontains "/auth/realms/prod" or
    vt.net.url.path icontains "/saml/login/alias/brand-sp" or
    (vt.net.url.path icontains "/auth/login" and vt.net.url.raw icontains "examplebrand")
  )"""
    pos_vec = TestVector(
        id="positive_brand_phishing_url",
        description="External newly observed URL mimicking brand login path triggers alert",
        expect=1,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={
                    "vt.net.url.new_url": True,
                    "vt.net.domain.root": "malicious-login.test",
                    "vt.net.domain.raw": "auth.malicious-login.test",
                    "vt.net.url.path": "/auth/login",
                    "vt.net.url.raw": "https://auth.malicious-login.test/auth/login?target=examplebrand",
                },
            ),
        ),
    )
    neg_vec = TestVector(
        id="negative_legitimate_corporate_domain",
        description="Legitimate corporate root domain is excluded",
        expect=0,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:05:00Z",
                payload={
                    "vt.net.url.new_url": True,
                    "vt.net.domain.root": "example.com",
                    "vt.net.domain.raw": "auth.example.com",
                    "vt.net.url.path": "/auth/realms/prod",
                    "vt.net.url.raw": "https://auth.example.com/auth/realms/prod",
                },
            ),
        ),
    )
    return RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000001",
            name="suspicious_brand_phishing_url",
            description="Detects brand phishing URLs",
            owners=("secops-team",),
            mitre={"initial-access": ("T1566.002",)},
            tags=("gti", "phishing"),
            references=("https://example.com",),
        ),
        logic=logic,
        deployment=BaseDeploymentConfig.from_dict({"enabled": True}),
        runbook=Runbook(context="ctx", triage="tri", response="resp"),
        tests=(pos_vec, neg_vec),
    )


def test_gti_replay_synthetic_url_rule_positive_and_negative_vectors() -> None:
    replay = GTIReplayAdapter(client=None)
    rule = _build_phishing_rule_with_vectors()

    pos_res = replay.run_test_vector(rule, rule.tests[0])
    assert pos_res.passed is True
    assert pos_res.matched_events_count == 1

    neg_res = replay.run_test_vector(rule, rule.tests[1])
    assert neg_res.passed is True
    assert neg_res.matched_events_count == 0


def test_gti_replay_synthetic_file_strings_rule() -> None:
    replay = GTIReplayAdapter(client=None)
    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000002",
            name="suspicious_pe_loader",
            description="Detects PE loader strings",
        ),
        logic="""import "pe"
import "vt"

strings:
  $s1 = "VirtualAllocEx" ascii
  $s2 = "WriteProcessMemory" nocase

condition:
  $s1 and $s2""",
        deployment=BaseDeploymentConfig.from_dict({"enabled": True}),
    )
    vec = TestVector(
        id="pos_strings",
        description="Matches both strings",
        expect=1,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={"sample_text": "Calling VirtualAllocEx and writeprocessmemory"},
            ),
        ),
    )
    res = replay.run_test_vector(rule, vec)
    assert res.passed is True
    assert res.matched_events_count == 1


def test_gti_replay_retrohunt_job_submission_and_polling() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    replay = GTIReplayAdapter(client=client, poll_interval_seconds=0.0)
    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000003",
            name="retro_goodware_check",
            description="Zero matches on goodware corpus",
        ),
        logic='strings:\n  $a = "SYNTHETIC_MALWARE_MARKER"\ncondition:\n  $a',
        deployment=BaseDeploymentConfig.from_dict({"enabled": True}),
    )
    vec = TestVector(
        id="retrohunt_goodware_zero_fp",
        description="Verify zero matches on GTI goodware corpus",
        expect=0,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={"mode": "retrohunt", "corpus": "goodware"},
            ),
        ),
    )

    calls: list[tuple[str, str]] = []

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        calls.append((method, path))
        if method == "POST" and path == "/intelligence/retrohunt_jobs":
            assert payload is not None
            assert payload["data"]["attributes"]["corpus"] == "goodware"
            return {
                "data": {
                    "type": "retrohunt_job",
                    "id": "retro_job_1",
                    "attributes": {"status": "running", "num_matches": 0},
                }
            }
        if method == "GET" and path == "/intelligence/retrohunt_jobs/retro_job_1":
            return {
                "data": {
                    "type": "retrohunt_job",
                    "id": "retro_job_1",
                    "attributes": {"status": "finished", "num_matches": 0},
                }
            }
        if method == "DELETE" and path == "/intelligence/retrohunt_jobs/retro_job_1":
            return {}
        raise AssertionError(f"Unexpected call: {method} {path}")

    with patch.object(client, "request", side_effect=fake_request):
        res = replay.run_test_vector(rule, vec)

    assert res.passed is True
    assert res.matched_events_count == 0
    assert ("POST", "/intelligence/retrohunt_jobs") in calls
    assert ("GET", "/intelligence/retrohunt_jobs/retro_job_1") in calls
    assert ("DELETE", "/intelligence/retrohunt_jobs/retro_job_1") in calls


def test_gti_replay_retrohunt_fails_closed_when_job_not_finished_and_unescapes_strings() -> None:
    cfg = GTIConfig(api_key="SYNTHETIC_TEST_KEY_000000")
    client = GTIClient(cfg, base_delay_seconds=0.0)
    replay = GTIReplayAdapter(client=client, poll_interval_seconds=0.0, max_poll_attempts=1)
    rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000004",
            name="retro_timeout_check",
            description="Retrohunt timeout must not pass expect=0",
        ),
        logic='strings:\n  $q = "say \\"hello\\""\ncondition:\n  $q',
        deployment=BaseDeploymentConfig.from_dict({"enabled": True}),
    )
    retro_vec = TestVector(
        id="retrohunt_timeout_expect_zero",
        description="Timed-out running job must fail even when expect is 0",
        expect=0,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={"mode": "retrohunt", "corpus": "goodware"},
            ),
        ),
    )

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if method == "POST" and path == "/intelligence/retrohunt_jobs":
            return {"data": {"type": "retrohunt_job", "id": "retro_job_timeout"}}
        if method == "GET" and path == "/intelligence/retrohunt_jobs/retro_job_timeout":
            return {
                "data": {
                    "type": "retrohunt_job",
                    "id": "retro_job_timeout",
                    "attributes": {"status": "running", "num_matches": None},
                }
            }
        if method == "DELETE" and path == "/intelligence/retrohunt_jobs/retro_job_timeout":
            return {}
        raise AssertionError(f"Unexpected call: {method} {path}")

    with patch.object(client, "request", side_effect=fake_request):
        res_retro = replay.run_test_vector(rule, retro_vec)
    assert res_retro.passed is False
    assert "did not finish" in res_retro.message

    unit_vec = TestVector(
        id="match_escaped_quotes",
        description="Matches unescaped double quotes in sample_text",
        expect=1,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={"sample_text": 'prefix say "hello" suffix'},
            ),
        ),
    )
    res_unit = replay.run_test_vector(rule, unit_vec)
    assert res_unit.passed is True


def test_gti_replay_supports_native_yarax_quantifiers_regex_defined_and_counts() -> None:
    replay = GTIReplayAdapter(client=None)

    # 1. Trackers & regex matches & defined
    tracker_rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000005",
            name="lh_corporate_analytics_tracker_cloned",
            description="Detects cloned tracker IDs",
        ),
        logic="""import "vt"

condition:
  (
    for any tracker in vt.net.url.trackers: (
      tracker.id == "G-ACME000001" or
      tracker.id == "GTM-ACME001"
    )
  ) and
  vt.net.domain.root != "acme.com" and
  vt.net.url.new_url and
  (
    (defined vt.net.url.analysis_stats.malicious and vt.net.url.analysis_stats.malicious >= 1) or
    vt.net.url.path matches /\\/(login|signin|sso|verify)\\b/i
  )""",
        deployment=BaseDeploymentConfig.from_dict({"enabled": True}),
    )
    pos_tracker = TestVector(
        id="pos_tracker",
        description="Matches cloned tracker on login path",
        expect=1,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={
                    "vt.net.url.trackers": [{"id": "G-ACME000001"}],
                    "vt.net.domain.root": "acme-login-portal.test",
                    "vt.net.url.new_url": True,
                    "vt.net.url.path": "/sso/auth",
                },
            ),
        ),
    )
    neg_tracker = TestVector(
        id="neg_tracker",
        description="Legitimate acme.com domain excluded",
        expect=0,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={
                    "vt.net.url.trackers": [{"id": "G-ACME000001"}],
                    "vt.net.domain.root": "acme.com",
                    "vt.net.url.new_url": True,
                    "vt.net.url.path": "/sso/auth",
                },
            ),
        ),
    )
    assert replay.run_test_vector(tracker_rule, pos_tracker).passed is True
    assert replay.run_test_vector(tracker_rule, neg_tracker).passed is True

    # 2. Regex strings, occurrence count (#bin1 + #bin2) > 8, size suffixes, and any of ($prefix_*)
    card_and_leak_rule = RuleEnvelope(
        metadata=RuleMetadata(
            id="8f14e45f-ceea-467a-a124-000000000006",
            name="lh_payment_card_and_secret_check",
            description="Detects card BIN counts and secret prefixes",
        ),
        logic="""import "vt"

strings:
  $bin1 = /377000[0-9]{10}/
  $bin2 = /491000[0-9]{10}/
  $org_domain = "acme.com" nocase wide ascii
  $org_name = "acme" fullword nocase wide ascii

condition:
  vt.metadata.new_file and
  filesize < 5MB and
  (#bin1 + #bin2) > 8 and
  any of ($org_*)""",
        deployment=BaseDeploymentConfig.from_dict({"enabled": True}),
    )
    nine_cards = " ".join(
        [f"377000111122223{i}" for i in range(5)] + [f"491000111122223{i}" for i in range(4)]
    )
    pos_cards = TestVector(
        id="pos_cards",
        description="9 cards + acme.com under 5MB triggers",
        expect=1,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={
                    "vt.metadata.new_file": True,
                    "filesize": 102400,
                    "sample_text": f"ACME Bank dump acme.com: {nine_cards}",
                },
            ),
        ),
    )
    neg_cards = TestVector(
        id="neg_cards",
        description="Only 2 cards does not exceed threshold of 8",
        expect=0,
        events=(
            TestEvent(
                timestamp="2026-10-15T12:00:00Z",
                payload={
                    "vt.metadata.new_file": True,
                    "filesize": 102400,
                    "sample_text": "ACME Bank dump acme.com: 3770001111222231 4910001111222232",
                },
            ),
        ),
    )
    assert replay.run_test_vector(card_and_leak_rule, pos_cards).passed is True
    assert replay.run_test_vector(card_and_leak_rule, neg_cards).passed is True

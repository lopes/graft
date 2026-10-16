import json
from pathlib import Path

import pytest

from graft.core.validation.mitre_validator import MitreValidator


@pytest.fixture
def mitre_validator() -> MitreValidator:
    return MitreValidator()


def test_valid_mitre_mapping_passes(mitre_validator: MitreValidator) -> None:
    mitre_data = {
        "execution": ["T1059.001", "T1059"],
        "persistence": ["T1547.001"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert errors == []
    assert mitre_validator.is_valid(mitre_data) is True


def test_unknown_tactic_rejected(mitre_validator: MitreValidator) -> None:
    mitre_data = {
        "invalid-tactic": ["T1059.001"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert len(errors) == 1
    assert errors[0].tactic == "invalid-tactic"
    assert "Unknown MITRE tactic" in errors[0].message
    assert mitre_validator.is_valid(mitre_data) is False


def test_unknown_technique_rejected(mitre_validator: MitreValidator) -> None:
    mitre_data = {
        "execution": ["T9999.999"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert len(errors) == 1
    assert errors[0].technique == "T9999.999"
    assert "Unknown MITRE technique" in errors[0].message
    assert mitre_validator.is_valid(mitre_data) is False


def test_technique_wrong_tactic_rejected_with_suggestion(
    mitre_validator: MitreValidator,
) -> None:
    # T1059.001 (PowerShell) belongs to execution, not initial-access
    mitre_data = {
        "initial-access": ["T1059.001"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert len(errors) == 1
    assert errors[0].tactic == "initial-access"
    assert errors[0].technique == "T1059.001"
    assert "does not belong to tactic 'initial-access'" in errors[0].message
    assert "execution" in errors[0].message
    assert mitre_validator.is_valid(mitre_data) is False


def test_unmapped_forwarder_pseudo_tactic_passes(mitre_validator: MitreValidator) -> None:
    mitre_data = {
        "none": ["T0000"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert errors == []
    assert mitre_validator.is_valid(mitre_data) is True


def test_unmapped_forwarder_technique_on_real_tactic_rejected(
    mitre_validator: MitreValidator,
) -> None:
    mitre_data = {
        "execution": ["T0000"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert len(errors) == 1
    assert "does not belong to tactic 'execution'" in errors[0].message
    assert mitre_validator.is_valid(mitre_data) is False


def test_mitre_stealth_and_defense_impairment(mitre_validator: MitreValidator) -> None:
    assert tuple(int(p) for p in mitre_validator.version.split(".")) >= (19, 2)
    assert "stealth" in mitre_validator.tactics
    assert "defense-impairment" in mitre_validator.tactics
    assert mitre_validator.tactics["stealth"] == {"id": "TA0005", "name": "Stealth"}
    assert mitre_validator.tactics["defense-impairment"] == {
        "id": "TA0112",
        "name": "Defense Impairment",
    }

    # T1685 belongs to defense-impairment
    valid_data = {"defense-impairment": ["T1685"]}
    assert mitre_validator.is_valid(valid_data) is True


def test_parse_attack_stix_and_analytics_bundles() -> None:
    from graft.core.validation.mitre_validator import (
        parse_attack_analytics_bundle,
        parse_attack_stix_bundle,
    )

    sample_stix = {
        "objects": [
            {
                "type": "x-mitre-collection",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "19.2",
            },
            {
                "type": "x-mitre-tactic",
                "x_mitre_deprecated": False,
                "x_mitre_shortname": "initial-access",
                "name": "Initial Access",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}],
            },
            {
                "type": "x-mitre-tactic",
                "x_mitre_deprecated": False,
                "x_mitre_shortname": "execution",
                "name": "Execution",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--active-1",
                "x_mitre_deprecated": False,
                "revoked": False,
                "name": "PowerShell",
                "x_mitre_platforms": ["Windows", "Linux"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--revoked-1",
                "x_mitre_deprecated": False,
                "revoked": True,
                "name": "PowerShell (Legacy)",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1086"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--deprecated-1",
                "x_mitre_deprecated": True,
                "revoked": False,
                "name": "Scripting",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1064"}],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--g1",
                "name": "APT41",
                "aliases": ["APT41", "Barium"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0096"}],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--m1",
                "name": "Code Signing",
                "description": "Enforce binary and script execution policies. Extra details here.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "M1045"}],
            },
            {
                "type": "x-mitre-data-component",
                "id": "x-mitre-data-component--dc1",
                "name": "Command Execution",
                "external_references": [{"source_name": "mitre-attack", "external_id": "DC0064"}],
            },
            {
                "type": "x-mitre-analytic",
                "id": "x-mitre-analytic--an1",
                "name": "Analytic 0101",
                "description": "Monitor PowerShell script block logging.",
                "x_mitre_platforms": ["Windows"],
                "x_mitre_log_source_references": [
                    {
                        "x_mitre_data_component_ref": "x-mitre-data-component--dc1",
                        "name": "WinEventLog:PowerShell",
                        "channel": "EventCode=4104",
                    }
                ],
                "x_mitre_mutable_elements": [
                    {"field": "AllowedSignedScripts", "description": "Signed admin scripts"}
                ],
                "external_references": [{"source_name": "mitre-attack", "external_id": "AN0101"}],
            },
            {
                "type": "x-mitre-detection-strategy",
                "id": "x-mitre-detection-strategy--det1",
                "name": "Detect PowerShell Execution",
                "x_mitre_analytic_refs": ["x-mitre-analytic--an1"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "DET0010"}],
            },
            {
                "type": "relationship",
                "relationship_type": "revoked-by",
                "source_ref": "attack-pattern--revoked-1",
                "target_ref": "attack-pattern--active-1",
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--g1",
                "target_ref": "attack-pattern--active-1",
            },
            {
                "type": "relationship",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m1",
                "target_ref": "attack-pattern--active-1",
            },
            {
                "type": "relationship",
                "relationship_type": "detects",
                "source_ref": "x-mitre-detection-strategy--det1",
                "target_ref": "attack-pattern--active-1",
            },
        ]
    }

    result = parse_attack_stix_bundle(sample_stix)
    assert result["version"] == "19.2"
    assert "initial-access" in result["tactics"]
    assert "defense-evasion" in result["legacy_tactics"]
    assert "T1059.001" in result["techniques"]
    t_info = result["techniques"]["T1059.001"]
    assert t_info["tactics"] == ["execution"]
    assert t_info["platforms"] == ["Linux", "Windows"]
    assert t_info["groups"] == ["G0096"]
    assert t_info["mitigations"] == ["M1045"]
    assert t_info["detection_strategies"] == ["DET0010"]
    assert t_info["data_components"] == ["DC0064"]

    assert result["inactive_techniques"]["T1086"] == {
        "name": "PowerShell (Legacy)",
        "status": "revoked",
        "revoked_by": "T1059.001",
    }
    assert result["inactive_techniques"]["T1064"] == {
        "name": "Scripting",
        "status": "deprecated",
        "revoked_by": None,
    }
    assert result["groups"]["G0096"] == {"name": "APT41", "aliases": ["APT41", "Barium"]}
    assert result["mitigations"]["M1045"]["name"] == "Code Signing"
    assert (
        result["mitigations"]["M1045"]["description"]
        == "Enforce binary and script execution policies."
    )
    assert result["data_components"]["DC0064"] == {"name": "Command Execution"}
    assert result["detection_strategies"]["DET0010"] == {
        "name": "Detect PowerShell Execution",
        "analytics": ["AN0101"],
    }

    analytics_res = parse_attack_analytics_bundle(sample_stix)
    assert analytics_res["version"] == "19.2"
    assert "AN0101" in analytics_res["analytics"]
    an = analytics_res["analytics"]["AN0101"]
    assert an["strategy_id"] == "DET0010"
    assert an["platforms"] == ["Windows"]
    assert an["log_sources"] == [
        {
            "data_component": "DC0064",
            "name": "WinEventLog:PowerShell",
            "channel": "EventCode=4104",
        }
    ]
    assert an["mutable_elements"] == [
        {"field": "AllowedSignedScripts", "description": "Signed admin scripts"}
    ]


def test_revoked_and_deprecated_technique_lint_hints(tmp_path: Path) -> None:
    matrix_file = tmp_path / "mitre_custom.json"
    matrix_file.write_text(
        json.dumps(
            {
                "version": "19.2",
                "tactics": {
                    "execution": {"id": "TA0002", "name": "Execution"},
                    "stealth": {"id": "TA0005", "name": "Stealth"},
                    "defense-impairment": {"id": "TA0112", "name": "Defense Impairment"},
                },
                "legacy_tactics": {
                    "defense-evasion": {
                        "id": "TA0005",
                        "replaced_by": ["stealth", "defense-impairment"],
                    }
                },
                "techniques": {
                    "T1059.001": {"name": "PowerShell", "tactics": ["execution"]},
                    "T1562.001": {
                        "name": "Disable or Modify Tools",
                        "tactics": ["defense-impairment"],
                    },
                    "T1027": {
                        "name": "Obfuscated Files or Information",
                        "tactics": ["stealth"],
                    },
                },
                "inactive_techniques": {
                    "T1086": {
                        "name": "PowerShell",
                        "status": "revoked",
                        "revoked_by": "T1059.001",
                    },
                    "T1064": {
                        "name": "Scripting",
                        "status": "deprecated",
                        "revoked_by": None,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    validator = MitreValidator(matrix_path=matrix_file)

    # 1. Revoked technique with replacement
    errs_revoked = validator.validate({"execution": ["T1086"]})
    assert len(errs_revoked) == 1
    assert errs_revoked[0].technique == "T1086"
    assert "revoked by 'T1059.001'" in errs_revoked[0].message
    assert "execution" in errs_revoked[0].message

    # 2. Deprecated technique without replacement
    errs_dep = validator.validate({"execution": ["T1064"]})
    assert len(errs_dep) == 1
    assert errs_dep[0].technique == "T1064"
    assert "deprecated" in errs_dep[0].message

    # 3. Legacy defense-evasion tactic with technique-specific v19 migration hints
    errs_legacy = validator.validate({"defense-evasion": ["T1562.001", "T1027"]})
    assert len(errs_legacy) == 1
    assert errs_legacy[0].tactic == "defense-evasion"
    assert "stealth" in errs_legacy[0].message
    assert "defense-impairment" in errs_legacy[0].message
    assert "T1562.001 -> ['defense-impairment']" in errs_legacy[0].message
    assert "T1027 -> ['stealth']" in errs_legacy[0].message

    # 4. reconstruct_mitre_mapping auto-upgrades revoked technique T1086 -> T1059.001
    reconstructed = validator.reconstruct_mitre_mapping(
        raw_tactics=["TA0002"],
        raw_techniques=["T1086"],
    )
    assert reconstructed == {"execution": ("T1059.001",)}


def test_check_upstream_mitre_version_and_offline_fallback() -> None:
    import io
    from unittest.mock import patch

    from graft.core.validation.mitre_validator import check_upstream_mitre_version

    sample_index = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [
                    {
                        "version": "20.0",
                        "url": "https://example.com/enterprise-attack-20.0.json",
                    }
                ],
            }
        ]
    }
    raw_bytes = json.dumps(sample_index).encode("utf-8")

    with patch("urllib.request.urlopen", return_value=io.BytesIO(raw_bytes)):
        status = check_upstream_mitre_version(
            current_version="19.2", index_url="https://example.com/index.json"
        )
    assert status["current_version"] == "19.2"
    assert status["latest_version"] == "20.0"
    assert status["update_available"] is True
    assert status["offline"] is False

    with patch("urllib.request.urlopen", side_effect=OSError("network unreachable")):
        offline_status = check_upstream_mitre_version(
            current_version="19.2", index_url="https://example.com/index.json"
        )
    assert offline_status["update_available"] is False
    assert offline_status["offline"] is True


def test_update_mitre_taxonomy(tmp_path: Path) -> None:
    import io
    from unittest.mock import patch

    from graft.core.validation.mitre_validator import update_mitre_taxonomy

    sample_stix = {
        "objects": [
            {
                "type": "x-mitre-collection",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "20.0",
            },
            {
                "type": "x-mitre-tactic",
                "x_mitre_deprecated": False,
                "x_mitre_shortname": "stealth",
                "name": "Stealth",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0005"}],
            },
        ]
    }
    raw_bytes = json.dumps(sample_stix).encode("utf-8")
    mock_resp = io.BytesIO(raw_bytes)
    target_file = tmp_path / "mitre_test.json"
    analytics_file = tmp_path / "mitre_analytics_test.json"

    with patch("urllib.request.urlopen", return_value=mock_resp):
        payload = update_mitre_taxonomy(
            source_url="http://example.com/stix.json",
            target_path=target_file,
            analytics_target_path=analytics_file,
        )

    assert payload["version"] == "20.0"
    assert target_file.is_file()
    assert analytics_file.is_file()
    saved = json.loads(target_file.read_text(encoding="utf-8"))
    assert "stealth" in saved["tactics"]


def test_resolve_tactic_and_technique_ids(mitre_validator: MitreValidator) -> None:
    from graft.core.validation.mitre_validator import get_default_mitre_validator

    assert get_default_mitre_validator() is get_default_mitre_validator()

    mitre_mapping = {
        "privilege-escalation": ("T1098.001", "T1078.004"),
        "persistence": ("T1098.001",),
        "none": ("T0000",),
    }
    assert mitre_validator.resolve_tactic_ids(mitre_mapping) == ("TA0003", "TA0004")
    assert mitre_validator.resolve_technique_ids(mitre_mapping) == ("T1078.004", "T1098.001")

    assert mitre_validator.resolve_tactic_ids({"none": ("T0000",)}) == ()
    assert mitre_validator.resolve_technique_ids({"none": ("T0000",)}) == ()


def test_reconstruct_mitre_mapping(mitre_validator: MitreValidator) -> None:
    reconstructed = mitre_validator.reconstruct_mitre_mapping(
        raw_tactics=["TA0003"],
        raw_techniques=["T1098.001"],
    )
    assert reconstructed == {"persistence": ("T1098.001",)}

    reconstructed_both = mitre_validator.reconstruct_mitre_mapping(
        raw_tactics=["ta0004", "TA0003"],
        raw_techniques=["t1098.001"],
    )
    assert reconstructed_both == {
        "persistence": ("T1098.001",),
        "privilege-escalation": ("T1098.001",),
    }

    reconstructed_no_tactic = mitre_validator.reconstruct_mitre_mapping(
        raw_tactics=[],
        raw_techniques=["T1098.001"],
    )
    assert reconstructed_no_tactic == {
        "persistence": ("T1098.001",),
        "privilege-escalation": ("T1098.001",),
    }

    reconstructed_shortname = mitre_validator.reconstruct_mitre_mapping(
        raw_tactics=["initial-access"],
        raw_techniques=["T1078.004"],
    )
    assert reconstructed_shortname == {"initial-access": ("T1078.004",)}

    assert (
        mitre_validator.reconstruct_mitre_mapping(
            raw_tactics=["TA0000", "TA9999"],
            raw_techniques=["T0000", "T9999.999"],
        )
        == {}
    )

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


def test_mitre_v192_stealth_and_defense_impairment(mitre_validator: MitreValidator) -> None:
    assert mitre_validator.version == "19.2"
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


def test_parse_attack_stix_bundle() -> None:
    from graft.core.validation.mitre_validator import parse_attack_stix_bundle

    sample_stix = {
        "objects": [
            {
                "type": "x-mitre-tactic",
                "x_mitre_deprecated": False,
                "x_mitre_shortname": "initial-access",
                "name": "Initial Access",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}],
            },
            {
                "type": "attack-pattern",
                "x_mitre_deprecated": False,
                "revoked": False,
                "name": "Spearphishing Link",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566.002"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
        ]
    }

    result = parse_attack_stix_bundle(sample_stix, version="19.2")
    assert result["version"] == "19.2"
    assert "initial-access" in result["tactics"]
    assert result["tactics"]["initial-access"] == {
        "id": "TA0001",
        "name": "Initial Access",
    }
    assert "none" in result["tactics"]
    assert result["tactics"]["none"] == {
        "id": "TA0000",
        "name": "Unmapped / Forwarded Alerts",
    }
    assert "T1566.002" in result["techniques"]
    assert result["techniques"]["T1566.002"]["tactics"] == ["initial-access"]
    assert "T0000" in result["techniques"]


def test_update_mitre_taxonomy(tmp_path: Path) -> None:
    import io
    from unittest.mock import patch

    from graft.core.validation.mitre_validator import update_mitre_taxonomy

    sample_stix = {
        "objects": [
            {
                "type": "x-mitre-tactic",
                "x_mitre_deprecated": False,
                "x_mitre_shortname": "stealth",
                "name": "Stealth",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0005"}],
            }
        ]
    }
    raw_bytes = json.dumps(sample_stix).encode("utf-8")
    mock_resp = io.BytesIO(raw_bytes)
    target_file = tmp_path / "mitre_test.json"

    with patch("urllib.request.urlopen", return_value=mock_resp):
        payload = update_mitre_taxonomy(
            source_url="http://example.com/stix.json", target_path=target_file
        )

    assert payload["version"] == "19.2"
    assert target_file.is_file()
    saved = json.loads(target_file.read_text(encoding="utf-8"))
    assert "stealth" in saved["tactics"]

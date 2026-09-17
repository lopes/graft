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
        "invalid_tactic": ["T1059.001"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert len(errors) == 1
    assert errors[0].tactic == "invalid_tactic"
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
    # T1059.001 (PowerShell) belongs to execution, not initial_access
    mitre_data = {
        "initial_access": ["T1059.001"],
    }
    errors = mitre_validator.validate(mitre_data)
    assert len(errors) == 1
    assert errors[0].tactic == "initial_access"
    assert errors[0].technique == "T1059.001"
    assert "does not belong to tactic 'initial_access'" in errors[0].message
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

from pathlib import Path

from graft.core.models.rule import BaseDeploymentConfig, RuleEnvelope, RuleMetadata, Runbook
from graft.core.validation.uniqueness_validator import (
    RuleUniquenessValidator,
)


def _make_rule(rule_id: str, rule_name: str) -> RuleEnvelope:
    metadata = RuleMetadata(
        id=rule_id,
        name=rule_name,
        description="Test rule",
    )
    return RuleEnvelope(
        metadata=metadata,
        logic="events:\n  $e\ncondition:\n  $e",
        deployment=BaseDeploymentConfig(),
        runbook=Runbook(),
    )


def test_unique_rules_across_different_engines_pass() -> None:
    validator = RuleUniquenessValidator()
    rule1 = _make_rule("id-1", "rule_one")
    rule2 = _make_rule("id-2", "rule_two")

    violations1 = validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/custom/r1.yaml")
    )
    violations2 = validator.add_and_validate(
        rule2, engine="crowdstrike", path=Path("rulesets/crowdstrike/custom/r2.yaml")
    )

    assert len(violations1) == 0
    assert len(violations2) == 0


def test_same_name_across_different_engines_is_allowed() -> None:
    validator = RuleUniquenessValidator()
    rule_sentinel = _make_rule("id-sentinel-1", "shared_rule_name")
    rule_crowdstrike = _make_rule("id-cs-1", "shared_rule_name")

    v1 = validator.add_and_validate(
        rule_sentinel, engine="sentinel", path=Path("rulesets/sentinel/custom/rule.yaml")
    )
    v2 = validator.add_and_validate(
        rule_crowdstrike, engine="crowdstrike", path=Path("rulesets/crowdstrike/custom/rule.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 0


def test_duplicate_id_across_different_engines_rejected() -> None:
    validator = RuleUniquenessValidator()
    rule_sentinel = _make_rule("duplicate-uuid-1234", "sentinel_rule")
    rule_crowdstrike = _make_rule("duplicate-uuid-1234", "crowdstrike_rule")

    v1 = validator.add_and_validate(
        rule_sentinel, engine="sentinel", path=Path("rulesets/sentinel/custom/r1.yaml")
    )
    v2 = validator.add_and_validate(
        rule_crowdstrike, engine="crowdstrike", path=Path("rulesets/crowdstrike/custom/r2.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 1
    assert v2[0].violation_type == "id"
    assert v2[0].rule_id == "duplicate-uuid-1234"
    assert "globally unique" in v2[0].message
    assert "crowdstrike" in v2[0].message
    assert "sentinel" in v2[0].message


def test_duplicate_id_within_same_engine_rejected() -> None:
    validator = RuleUniquenessValidator()
    rule1 = _make_rule("duplicate-uuid-1234", "first_rule")
    rule2 = _make_rule("duplicate-uuid-1234", "second_rule")

    v1 = validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/custom/r1.yaml")
    )
    v2 = validator.add_and_validate(
        rule2, engine="sentinel", path=Path("rulesets/sentinel/custom/r2.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 1
    assert v2[0].violation_type == "id"


def test_duplicate_name_within_same_engine_rejected() -> None:
    validator = RuleUniquenessValidator()
    rule1 = _make_rule("id-1", "duplicate_rule_name")
    rule2 = _make_rule("id-2", "duplicate_rule_name")

    v1 = validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/custom/r1.yaml")
    )
    v2 = validator.add_and_validate(
        rule2, engine="sentinel", path=Path("rulesets/sentinel/custom/r2.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 1
    assert v2[0].violation_type == "name"
    assert v2[0].rule_name == "duplicate_rule_name"
    assert "unique within their engine" in v2[0].message


def test_validator_reset() -> None:
    validator = RuleUniquenessValidator()
    rule1 = _make_rule("id-1", "rule_name")
    validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/custom/r1.yaml")
    )
    validator.reset()

    # After reset, the same rule can be registered without collision
    v = validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/custom/r1.yaml")
    )
    assert len(v) == 0


def test_duplicate_managed_id_within_same_engine_rejected() -> None:
    from graft.core.models.rule import ManagedRuleRef

    validator = RuleUniquenessValidator()
    rule1 = RuleEnvelope(
        metadata=RuleMetadata(id="id-1", name="managed_one", description="First"),
        runbook=Runbook(),
        managed=ManagedRuleRef(id="f5533b66-9327-9880-93e6-75a738ac2345"),
    )
    rule2 = RuleEnvelope(
        metadata=RuleMetadata(id="id-2", name="managed_two", description="Second"),
        runbook=Runbook(),
        managed=ManagedRuleRef(id="f5533b66-9327-9880-93e6-75a738ac2345"),
    )

    v1 = validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/managed/m1.yaml")
    )
    v2 = validator.add_and_validate(
        rule2, engine="sentinel", path=Path("rulesets/sentinel/managed/m2.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 1
    assert v2[0].violation_type == "managed_id"
    assert "f5533b66-9327-9880-93e6-75a738ac2345" in v2[0].message


def test_same_managed_id_across_different_engines_allowed() -> None:
    from graft.core.models.rule import ManagedRuleRef

    validator = RuleUniquenessValidator()
    rule_sentinel = RuleEnvelope(
        metadata=RuleMetadata(id="id-1", name="managed_one", description="First"),
        runbook=Runbook(),
        managed=ManagedRuleRef(id="shared-vendor-id-100"),
    )
    rule_cs = RuleEnvelope(
        metadata=RuleMetadata(id="id-2", name="managed_two", description="Second"),
        runbook=Runbook(),
        managed=ManagedRuleRef(id="shared-vendor-id-100"),
    )

    v1 = validator.add_and_validate(
        rule_sentinel, engine="sentinel", path=Path("rulesets/sentinel/managed/m1.yaml")
    )
    v2 = validator.add_and_validate(
        rule_cs, engine="crowdstrike", path=Path("rulesets/crowdstrike/managed/m1.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 0


def test_duplicate_file_stem_within_same_engine_rejected() -> None:
    validator = RuleUniquenessValidator()
    rule1 = _make_rule("id-1", "first_internal_name")
    rule2 = _make_rule("id-2", "second_internal_name")
    rule3 = _make_rule("id-3", "third_internal_name")

    v1 = validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/custom/shared_stem.yaml")
    )
    # Same directory, .yml vs .yaml collision with different metadata.name
    v2 = validator.add_and_validate(
        rule2, engine="sentinel", path=Path("rulesets/sentinel/custom/shared_stem.yml")
    )
    # custom/ vs managed/ stem collision within the same engine
    v3 = validator.add_and_validate(
        rule3, engine="sentinel", path=Path("rulesets/sentinel/managed/shared_stem.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 1
    assert v2[0].violation_type == "file_stem"
    assert "shared_stem" in v2[0].message
    assert len(v3) == 1
    assert v3[0].violation_type == "file_stem"


def test_same_file_stem_across_different_engines_allowed() -> None:
    validator = RuleUniquenessValidator()
    rule1 = _make_rule("id-1", "first_name")
    rule2 = _make_rule("id-2", "second_name")

    v1 = validator.add_and_validate(
        rule1, engine="sentinel", path=Path("rulesets/sentinel/custom/shared_stem.yaml")
    )
    v2 = validator.add_and_validate(
        rule2, engine="crowdstrike", path=Path("rulesets/crowdstrike/custom/shared_stem.yaml")
    )

    assert len(v1) == 0
    assert len(v2) == 0

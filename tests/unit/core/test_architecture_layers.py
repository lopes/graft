import ast
import dataclasses
import json
import re
import sys
import tomllib
from pathlib import Path

from graft.core.engine_registry import EngineRegistry
from graft.core.loader import (
    dataset_to_dict,
    dump_dataset_to_yaml,
    dump_rule_to_yaml,
    load_dataset_from_yaml,
    load_rule_from_yaml,
    rule_to_dict,
)
from graft.core.models.dataset import DatasetEnvelope, DatasetMetadata
from graft.core.models.rule import (
    BaseDeploymentConfig,
    ManagedRuleRef,
    RuleEnvelope,
    RuleMetadata,
    Runbook,
    TestEvent,
    TestVector,
)

# referencing is jsonschema's companion $ref registry module for Draft 2020-12
ALLOWED_THIRD_PARTY_IMPORTS = {"yaml", "jsonschema", "referencing"}
ALLOWED_PYPROJECT_DEPENDENCIES = {"pyyaml", "jsonschema"}
_DEP_NAME_RE = re.compile(r"^([a-zA-Z0-9_.-]+)")


def _extract_imports(py_path: Path) -> list[str]:
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
    return modules


def test_stdlib_first_runtime_imports() -> None:
    allowed_roots = sys.stdlib_module_names | {"graft"} | ALLOWED_THIRD_PARTY_IMPORTS
    violations: list[str] = []

    for py_path in sorted(Path("src/graft").rglob("*.py")):
        for mod in _extract_imports(py_path):
            root_mod = mod.split(".", 1)[0]
            if root_mod not in allowed_roots:
                violations.append(
                    f"{py_path}: imports disallowed non-stdlib module '{mod}' "
                    f"(only stdlib, pyyaml, and jsonschema are permitted)"
                )

    assert not violations, "Stdlib-First policy violations:\n" + "\n".join(violations)

    pyproject_data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    raw_deps: list[str] = pyproject_data.get("project", {}).get("dependencies", [])
    dep_names = {
        m.group(1).lower() for dep in raw_deps if (m := _DEP_NAME_RE.match(dep)) is not None
    }
    assert dep_names == ALLOWED_PYPROJECT_DEPENDENCIES, (
        f"pyproject.toml runtime dependencies {sorted(dep_names)} must match "
        f"{sorted(ALLOWED_PYPROJECT_DEPENDENCIES)}"
    )


def test_hexagonal_import_boundaries() -> None:
    violations: list[str] = []
    mitre_validator_path = Path("src/graft/core/validation/mitre_validator.py")

    for py_path in sorted(Path("src/graft").rglob("*.py")):
        imports = _extract_imports(py_path)
        parts = py_path.parts

        if py_path.is_relative_to("src/graft/core/models"):
            for mod in imports:
                root_mod = mod.split(".", 1)[0]
                if root_mod == "graft" and not mod.startswith("graft.core.models"):
                    violations.append(
                        f"{py_path}: domain model imports higher layer '{mod}' "
                        "(models may only import stdlib and graft.core.models)"
                    )
                elif root_mod not in sys.stdlib_module_names and root_mod != "graft":
                    violations.append(
                        f"{py_path}: domain model imports third-party module '{mod}' "
                        "(models must remain pure stdlib dataclasses)"
                    )

        elif py_path.is_relative_to("src/graft/core/ports"):
            for mod in imports:
                root_mod = mod.split(".", 1)[0]
                if root_mod == "graft" and not (
                    mod.startswith("graft.core.models") or mod.startswith("graft.core.ports")
                ):
                    violations.append(
                        f"{py_path}: port protocol imports higher layer '{mod}' "
                        "(ports may only import stdlib, graft.core.models, and graft.core.ports)"
                    )
                elif root_mod not in sys.stdlib_module_names and root_mod != "graft":
                    violations.append(
                        f"{py_path}: port protocol imports third-party module '{mod}' "
                        "(ports must remain pure stdlib typing.Protocol interfaces)"
                    )

        elif py_path.is_relative_to("src/graft/core"):
            for mod in imports:
                if mod.startswith(("graft.cli", "graft.engines")):
                    violations.append(
                        f"{py_path}: driving core imports outer adapter '{mod}' "
                        "(core must never import graft.cli or graft.engines)"
                    )
                if (
                    mod.startswith(("urllib.request", "http.client"))
                    and py_path != mitre_validator_path
                ):
                    violations.append(
                        f"{py_path}: driving core imports HTTP client '{mod}' "
                        "(network transports belong in driven engine adapters)"
                    )

        elif py_path.is_relative_to("src/graft/engines") and len(parts) >= 4:
            own_engine = parts[3]
            for mod in imports:
                if mod.startswith("graft.cli"):
                    violations.append(
                        f"{py_path}: engine adapter '{own_engine}' imports driving CLI '{mod}'"
                    )
                elif mod.startswith("graft.engines.") and not mod.startswith(
                    f"graft.engines.{own_engine}"
                ):
                    violations.append(
                        f"{py_path}: engine adapter '{own_engine}' imports another engine '{mod}'"
                    )

        elif py_path.is_relative_to("src/graft/cli"):
            for mod in imports:
                if mod.startswith("graft.engines"):
                    violations.append(
                        f"{py_path}: driving CLI statically imports concrete engine '{mod}' "
                        "(use EngineRegistry and EngineAdapter port protocols)"
                    )

    assert not violations, "Hexagonal architecture boundary violations:\n" + "\n".join(violations)


def test_schema_and_dataclass_completeness() -> None:
    schemas_dir = Path("src/graft/core/schemas")
    custom_schema = json.loads(
        (schemas_dir / "base_custom.schema.json").read_text(encoding="utf-8")
    )
    managed_schema = json.loads(
        (schemas_dir / "base_managed.schema.json").read_text(encoding="utf-8")
    )
    dataset_schema = json.loads(
        (schemas_dir / "base_dataset.schema.json").read_text(encoding="utf-8")
    )

    envelope_fields = {f.name for f in dataclasses.fields(RuleEnvelope)}
    schema_envelope_props = set(custom_schema["properties"].keys()) | set(
        managed_schema["properties"].keys()
    )
    assert envelope_fields == schema_envelope_props, (
        f"RuleEnvelope fields {sorted(envelope_fields)} out of sync with "
        f"base custom/managed schema properties {sorted(schema_envelope_props)}"
    )

    rule_meta_fields = {f.name for f in dataclasses.fields(RuleMetadata)}
    assert rule_meta_fields == set(custom_schema["properties"]["metadata"]["properties"].keys())
    assert rule_meta_fields == set(managed_schema["properties"]["metadata"]["properties"].keys())

    runbook_fields = {f.name for f in dataclasses.fields(Runbook)}
    assert runbook_fields == set(custom_schema["properties"]["runbook"]["properties"].keys())
    assert runbook_fields == set(managed_schema["properties"]["runbook"]["properties"].keys())

    managed_ref_fields = {f.name for f in dataclasses.fields(ManagedRuleRef)}
    assert managed_ref_fields == set(managed_schema["properties"]["managed"]["properties"].keys())

    test_vec_fields = {f.name for f in dataclasses.fields(TestVector)}
    custom_test_props = custom_schema["properties"]["tests"]["items"]["properties"]
    assert test_vec_fields == set(custom_test_props.keys())

    test_event_fields = {f.name for f in dataclasses.fields(TestEvent)}
    custom_event_props = custom_test_props["events"]["items"]["properties"]
    assert test_event_fields == set(custom_event_props.keys())

    dataset_fields = {f.name for f in dataclasses.fields(DatasetEnvelope)} - {"deprecated"}
    assert dataset_fields == set(dataset_schema["properties"].keys())

    dataset_meta_fields = {f.name for f in dataclasses.fields(DatasetMetadata)}
    assert dataset_meta_fields == set(dataset_schema["properties"]["metadata"]["properties"].keys())

    sample_custom = RuleEnvelope(
        metadata=RuleMetadata(
            id="11111111-2222-3333-4444-555555555555",
            name="completeness_probe",
            description="Completeness check rule",
            owners=("team-a",),
            mitre={"execution": ("T1059",)},
            tags=("test",),
            references=("https://example.com",),
        ),
        logic="condition: true",
        deployment=BaseDeploymentConfig(enabled=True, alerting=True, run_frequency="live"),
        runbook=Runbook(context="ctx", triage="tri", response="resp"),
        tests=(
            TestVector(
                id="vec_1",
                description="desc",
                expect=1,
                events=(TestEvent(timestamp="2026-01-01T00:00:00Z", payload={"k": "v"}),),
            ),
        ),
    )
    dumped_custom = rule_to_dict(sample_custom)
    assert set(dumped_custom.keys()) == set(custom_schema["properties"].keys())
    assert set(dumped_custom["metadata"].keys()) == rule_meta_fields
    assert set(dumped_custom["deployment"].keys()) == {
        f.name for f in dataclasses.fields(BaseDeploymentConfig)
    }

    sample_dataset = DatasetEnvelope(
        metadata=DatasetMetadata(
            name="sample_items",
            description="Sample dataset",
            owners=("team-a",),
            tags=("tag-a",),
            references=("https://example.com",),
        ),
        values=("val1",),
    )
    dumped_ds = dataset_to_dict(sample_dataset)
    assert set(dumped_ds.keys()) == dataset_fields
    assert set(dumped_ds["metadata"].keys()) == dataset_meta_fields


def test_repository_corpora_lossless_round_trip(tmp_path: Path) -> None:
    datasets_dir = Path("datasets")
    if datasets_dir.is_dir():
        for ds_path in sorted(datasets_dir.rglob("*.yaml")):
            if any(part.startswith("_") for part in ds_path.relative_to(datasets_dir).parts):
                continue
            original_ds = load_dataset_from_yaml(ds_path)
            roundtrip_path = tmp_path / "datasets" / ds_path.name
            dump_dataset_to_yaml(original_ds, roundtrip_path)
            reloaded_ds = load_dataset_from_yaml(roundtrip_path)
            assert reloaded_ds == original_ds, f"Dataset round-trip mismatch for {ds_path}"

    registry = EngineRegistry()
    rulesets_dir = Path("rulesets")
    if rulesets_dir.is_dir():
        for rule_path in sorted(rulesets_dir.rglob("*.yaml")):
            rel_parts = rule_path.relative_to(rulesets_dir).parts
            if any(part.startswith("_") for part in rel_parts) or rule_path.name in (
                "index.yaml",
                "index.yml",
            ):
                continue
            engine_name = rel_parts[0]
            original_rule = load_rule_from_yaml(rule_path)
            sub_dir = "managed" if original_rule.is_managed else "custom"
            roundtrip_rule_path = tmp_path / "rulesets" / engine_name / sub_dir / rule_path.name
            dump_rule_to_yaml(original_rule, roundtrip_rule_path)
            reloaded_rule = load_rule_from_yaml(roundtrip_rule_path)
            assert reloaded_rule == original_rule, f"Rule round-trip mismatch for {rule_path}"

            if not original_rule.is_managed:
                adapter = registry.load_adapter(engine_name)
                assert adapter.are_rules_equal(original_rule, reloaded_rule)

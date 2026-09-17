import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


@dataclass(frozen=True)
class ValidationErrorDetail:
    path: str
    message: str
    validator: str


class SchemaValidator:
    def __init__(self, schemas_dir: Path | None = None) -> None:
        if schemas_dir is None:
            schemas_dir = self._find_schemas_dir()
        self._schemas_dir = schemas_dir
        self._registry: Registry[Any] = Registry()
        self._validators: dict[str, Draft202012Validator] = {}
        self._load_schemas()

    def _find_schemas_dir(self) -> Path:
        current = Path(__file__).resolve().parent
        for parent in [current, *current.parents]:
            candidate = parent / "schemas"
            if candidate.is_dir() and (candidate / "base_rule.schema.json").exists():
                return candidate
        cwd_candidate = Path.cwd() / "schemas"
        if cwd_candidate.is_dir() and (cwd_candidate / "base_rule.schema.json").exists():
            return cwd_candidate
        raise FileNotFoundError(
            "Could not locate schemas/ directory containing base_rule.schema.json"
        )

    def _load_schemas(self) -> None:
        schema_files = list(self._schemas_dir.glob("*.schema.json"))
        loaded_resources: dict[str, Resource[dict[str, Any]]] = {}

        for sf in schema_files:
            schema_data = json.loads(sf.read_text(encoding="utf-8"))
            schema_id = str(schema_data.get("$id", sf.name))
            resource = Resource.from_contents(schema_data)
            loaded_resources[schema_id] = resource
            loaded_resources[sf.name] = resource

        registry: Registry[Any] = Registry()
        for uri, res in loaded_resources.items():
            registry = registry.with_resource(uri, res)
        self._registry = registry

        for sf in schema_files:
            schema_data = json.loads(sf.read_text(encoding="utf-8"))
            name = sf.name.replace(".schema.json", "")
            validator = Draft202012Validator(schema_data, registry=self._registry)
            self._validators[name] = validator
            self._validators[sf.name] = validator

    def validate(
        self, instance: object, schema_name: str = "secops_custom"
    ) -> list[ValidationErrorDetail]:
        validator = self._validators.get(schema_name)
        if validator is None:
            available = [k for k in self._validators if not k.endswith(".schema.json")]
            raise KeyError(f"Unknown schema '{schema_name}'. Available schemas: {available}")

        errors: list[ValidationErrorDetail] = []
        for err in validator.iter_errors(instance):
            path_str = ".".join(str(p) for p in err.absolute_path)
            errors.append(
                ValidationErrorDetail(
                    path=path_str,
                    message=err.message,
                    validator=str(err.validator or ""),
                )
            )
        return errors

    def is_valid(self, instance: object, schema_name: str = "secops_custom") -> bool:
        return len(self.validate(instance, schema_name=schema_name)) == 0

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
    def __init__(self, schemas_dir: Path | None = None, engines_dir: Path | None = None) -> None:
        if schemas_dir is None:
            schemas_dir = self._find_schemas_dir()
        self._schemas_dir = schemas_dir
        if engines_dir is None:
            engines_dir = self._find_engines_dir()
        self._engines_dir = engines_dir
        self._registry: Registry[Any] = Registry()
        self._validators: dict[str, Draft202012Validator] = {}
        self._load_schemas()

    def _find_schemas_dir(self) -> Path:
        primary = Path(__file__).resolve().parent.parent / "schemas"
        if primary.is_dir() and (primary / "base_custom.schema.json").exists():
            return primary
        current = Path(__file__).resolve().parent
        for parent in [current, *current.parents]:
            candidate_core = parent / "src" / "graft" / "core" / "schemas"
            if candidate_core.is_dir() and (candidate_core / "base_custom.schema.json").exists():
                return candidate_core
            candidate = parent / "schemas"
            if candidate.is_dir() and (candidate / "base_custom.schema.json").exists():
                return candidate
        cwd_candidate = Path.cwd() / "src" / "graft" / "core" / "schemas"
        if cwd_candidate.is_dir() and (cwd_candidate / "base_custom.schema.json").exists():
            return cwd_candidate
        cwd_root = Path.cwd() / "schemas"
        if cwd_root.is_dir() and (cwd_root / "base_custom.schema.json").exists():
            return cwd_root
        raise FileNotFoundError(
            "Could not locate schemas directory containing base_custom.schema.json"
        )

    def _find_engines_dir(self) -> Path | None:
        primary = Path(__file__).resolve().parent.parent.parent / "engines"
        if primary.is_dir():
            return primary
        current = Path(__file__).resolve().parent
        for parent in [current, *current.parents]:
            candidate_src = parent / "src" / "graft" / "engines"
            if candidate_src.is_dir():
                return candidate_src
            candidate = parent / "engines"
            if candidate.is_dir():
                return candidate
        cwd_candidate = Path.cwd() / "src" / "graft" / "engines"
        if cwd_candidate.is_dir():
            return cwd_candidate
        return None

    def _load_schemas(self) -> None:
        schema_entries: list[tuple[Path, str | None]] = [
            (sf, None) for sf in self._schemas_dir.glob("*.schema.json")
        ]

        if self._engines_dir and self._engines_dir.is_dir():
            for item in sorted(self._engines_dir.iterdir()):
                if item.is_dir() and not item.name.startswith(("_", ".")):
                    eng_schemas = item / "schemas"
                    if eng_schemas.is_dir():
                        for sf in eng_schemas.glob("*.schema.json"):
                            schema_entries.append((sf, item.name))

        loaded_resources: dict[str, Resource[dict[str, Any]]] = {}
        parsed_schemas: list[tuple[Path, str | None, dict[str, Any]]] = []

        for sf, engine_name in schema_entries:
            schema_data = json.loads(sf.read_text(encoding="utf-8"))
            parsed_schemas.append((sf, engine_name, schema_data))

            schema_id = str(schema_data.get("$id", sf.name))
            resource = Resource.from_contents(schema_data)
            loaded_resources[schema_id] = resource
            loaded_resources[sf.name] = resource

        registry: Registry[Any] = Registry()
        for uri, res in loaded_resources.items():
            registry = registry.with_resource(uri, res)
        self._registry = registry

        for sf, engine_name, schema_data in parsed_schemas:
            stem = sf.name.replace(".schema.json", "")
            validator = Draft202012Validator(schema_data, registry=self._registry)

            if engine_name is not None:
                self._validators[f"{engine_name}:{stem}"] = validator
                self._validators[f"{engine_name}_{stem}"] = validator
            else:
                self._validators[stem] = validator

            self._validators[sf.name] = validator
            schema_id = str(schema_data.get("$id", ""))
            if schema_id:
                self._validators[schema_id] = validator

    def available_schemas(self) -> list[str]:
        return sorted([k for k in self._validators if not k.endswith(".schema.json")])

    def validate(
        self, instance: object, schema_name: str = "base_custom"
    ) -> list[ValidationErrorDetail]:
        validator = self._validators.get(schema_name)
        if validator is None:
            raise KeyError(
                f"Unknown schema '{schema_name}'. Available schemas: {self.available_schemas()}"
            )

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

    def is_valid(self, instance: object, schema_name: str = "base_custom") -> bool:
        return len(self.validate(instance, schema_name=schema_name)) == 0

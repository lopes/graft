from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

import yaml

from graft.core.models.engine import EngineCapabilities, EngineManifest
from graft.core.ports.engine import EngineAdapter
from graft.core.validation.schema_validator import SchemaValidator

logger = logging.getLogger("graft.core.engine_registry")


class EngineError(Exception):
    pass


class EngineNotFoundError(EngineError):
    pass


class EngineManifestLoadError(EngineError):
    pass


RESERVED_CORE_COMMANDS = frozenset({"lint", "export", "update-mitre", "new", "help"})


class EngineRegistry:
    def __init__(self, engines_dir: Path | None = None, strict: bool = False) -> None:
        if engines_dir is None:
            self._engines_dir = self._find_default_engines_dir()
        else:
            self._engines_dir = engines_dir
        self._strict = strict
        self._manifests: dict[str, EngineManifest] = {}
        self._errors: dict[str, str] = {}
        self._discover()

    @staticmethod
    def _find_default_engines_dir() -> Path:
        core_dir = Path(__file__).resolve().parent
        candidate = core_dir.parent / "engines"
        if candidate.is_dir():
            return candidate
        cwd_candidate = Path.cwd() / "src" / "graft" / "engines"
        if cwd_candidate.is_dir():
            return cwd_candidate
        return candidate

    def _discover(self) -> None:
        if not self._engines_dir.is_dir():
            return

        validator = SchemaValidator()
        for item in sorted(self._engines_dir.iterdir()):
            if not item.is_dir() or item.name.startswith(("_", ".")):
                continue
            manifest_file = item / "engine.yaml"
            if not manifest_file.is_file():
                continue

            try:
                manifest = self._load_manifest_file(manifest_file, validator)
                self._manifests[manifest.name] = manifest
            except Exception as exc:
                logger.warning("Failed loading engine manifest at %s: %s", manifest_file, exc)
                self._errors[item.name] = str(exc)
                if self._strict:
                    raise EngineManifestLoadError(f"Error loading {manifest_file}: {exc}") from exc

    def _load_manifest_file(self, path: Path, validator: SchemaValidator) -> EngineManifest:
        try:
            raw_data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise EngineManifestLoadError(f"YAML parsing error in {path}: {exc}") from exc

        if not isinstance(raw_data, dict):
            raise EngineManifestLoadError(f"Engine manifest at {path} must be a YAML mapping")

        errors = validator.validate(raw_data, schema_name="engine_manifest")
        if errors:
            err_details = "; ".join(f"{e.path}: {e.message}" for e in errors)
            raise EngineManifestLoadError(
                f"Manifest schema validation failed for {path}: {err_details}"
            )

        name = str(raw_data["name"])
        if name in RESERVED_CORE_COMMANDS:
            raise EngineManifestLoadError(
                f"Engine name '{name}' is a reserved 1st-order command keyword"
            )

        caps_raw = raw_data.get("capabilities", {})
        capabilities = EngineCapabilities(
            custom_rules=bool(caps_raw.get("custom_rules", True)),
            syntax_verification=bool(caps_raw.get("syntax_verification", False)),
            managed_rules=bool(caps_raw.get("managed_rules", False)),
            replay_testing=bool(caps_raw.get("replay_testing", False)),
        )

        env_vars_raw = raw_data.get("env_vars", {})
        req_env = tuple(str(v) for v in env_vars_raw.get("required", ()))
        opt_env = tuple(str(v) for v in env_vars_raw.get("optional", ()))
        envs = tuple(str(e) for e in raw_data.get("environments", ("staging", "production")))

        return EngineManifest(
            name=str(raw_data["name"]),
            display_name=str(raw_data["display_name"]),
            description=str(raw_data["description"]),
            adapter_class=str(raw_data["adapter_class"]),
            capabilities=capabilities,
            environments=envs,
            required_env_vars=req_env,
            optional_env_vars=opt_env,
        )

    def list_engines(self) -> tuple[EngineManifest, ...]:
        return tuple(self._manifests.values())

    def has(self, name: str) -> bool:
        return name in self._manifests

    def get(self, name: str) -> EngineManifest:
        if name in self._manifests:
            return self._manifests[name]
        if name in self._errors:
            raise EngineManifestLoadError(
                f"Engine '{name}' has invalid manifest: {self._errors[name]}"
            )
        raise EngineNotFoundError(
            f"Engine '{name}' not found in registry. Available: {list(self._manifests.keys())}"
        )

    def get_engine_dir(self, name: str) -> Path:
        manifest = self.get(name)
        return self._engines_dir / manifest.name

    def load_adapter(self, name: str, env: str = "production") -> EngineAdapter:
        manifest = self.get(name)
        target = manifest.adapter_class
        if ":" not in target:
            raise EngineError(
                f"Invalid adapter_class format '{target}'. Expected 'module:ClassName'"
            )

        module_path, class_name = target.split(":", 1)
        try:
            module = importlib.import_module(module_path)
            adapter_cls = getattr(module, class_name)
        except (ImportError, AttributeError) as exc:
            raise EngineError(f"Failed loading adapter class '{target}': {exc}") from exc

        instance = adapter_cls(env=env)
        if not isinstance(instance, EngineAdapter):
            raise EngineError(f"Class '{target}' does not conform to EngineAdapter protocol")
        return instance

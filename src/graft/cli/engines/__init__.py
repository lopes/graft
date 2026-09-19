from __future__ import annotations

import argparse
import importlib
import pkgutil

from graft.cli.engine_controller import register_engine_commands
from graft.core.engine_registry import EngineRegistry


def discover_and_register_engines(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    registered_names: set[str] = set()

    # 1. Discover and register pluggable engines with engine.yaml manifests
    registry = EngineRegistry()
    for manifest in registry.list_engines():
        register_engine_commands(subparsers, manifest, registry)
        registered_names.add(manifest.name)

    # 2. Backward compatibility: Register legacy CLI modules not yet migrated to engine.yaml
    for _, module_name, is_pkg in pkgutil.iter_modules(__path__):
        if not is_pkg and not module_name.startswith("_") and module_name not in registered_names:
            mod = importlib.import_module(f"graft.cli.engines.{module_name}")
            if hasattr(mod, "register_engine"):
                mod.register_engine(subparsers)

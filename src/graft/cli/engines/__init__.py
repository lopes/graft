from __future__ import annotations

import argparse
import importlib
import pkgutil


def discover_and_register_engines(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    for _, module_name, is_pkg in pkgutil.iter_modules(__path__):
        if not is_pkg and not module_name.startswith("_"):
            mod = importlib.import_module(f"graft.cli.engines.{module_name}")
            if hasattr(mod, "register_engine"):
                mod.register_engine(subparsers)

from typing import Protocol

from graft.core.models.compiler import CompilationResult


class RuleCompilerPort(Protocol):
    def verify_syntax(self, rule_text: str) -> CompilationResult: ...

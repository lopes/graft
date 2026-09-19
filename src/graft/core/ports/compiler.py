from typing import Protocol

from graft.core.models.compiler import CompilationResult
from graft.core.models.rule import RuleEnvelope


class RuleCompilerPort(Protocol):
    def verify_syntax(self, rule_text: str) -> CompilationResult: ...

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult: ...

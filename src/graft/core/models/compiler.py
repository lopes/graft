from dataclasses import dataclass, field


@dataclass(frozen=True)
class CompilationDiagnostic:
    line: int
    column: int
    message: str
    severity: str = "ERROR"


@dataclass(frozen=True)
class CompilationResult:
    success: bool
    diagnostics: tuple[CompilationDiagnostic, ...] = ()
    raw_response: dict[str, object] = field(default_factory=dict)

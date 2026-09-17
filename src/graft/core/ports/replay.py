from dataclasses import dataclass
from typing import Protocol

from graft.core.models.rule import RuleEnvelope, TestVector


@dataclass(frozen=True)
class ReplayResult:
    test_id: str
    passed: bool
    message: str = ""
    matched_events_count: int = 0


class ReplayHarnessPort(Protocol):
    def run_test_vector(self, rule: RuleEnvelope, vector: TestVector) -> ReplayResult: ...

    def is_available(self) -> bool: ...

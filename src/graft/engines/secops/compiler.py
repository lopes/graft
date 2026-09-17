from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.rule import RuleEnvelope
from graft.core.ports.compiler import RuleCompilerPort
from graft.engines.secops.client import SecOpsClient


def synthesize_yaral_rule(rule: RuleEnvelope) -> tuple[str, int]:
    meta_id = rule.metadata.id
    meta_desc = rule.metadata.description.replace('"', '\\"')
    meta_status = rule.metadata.status

    header_lines = [
        f"rule {rule.metadata.name} {{",
        "  meta:",
        f'    id = "{meta_id}"',
        f'    description = "{meta_desc}"',
        f'    status = "{meta_status}"',
    ]
    header_offset = len(header_lines)
    rule_text = "\n".join(header_lines) + "\n" + rule.logic.strip() + "\n}\n"
    return rule_text, header_offset


def _parse_int_field(value: object, default: int = 1) -> int:
    if isinstance(value, (int, str)) and str(value).isdigit():
        return int(str(value))
    return default


class SecOpsCompilerAdapter(RuleCompilerPort):
    def __init__(self, client: SecOpsClient) -> None:
        self._client = client

    def verify_syntax(self, rule_text: str) -> CompilationResult:
        response = self._client.request(
            "POST",
            ":verifyRuleText",
            body={"ruleText": rule_text},
        )
        return self._parse_response(response, header_offset=0, rule_text=rule_text)

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        rule_text, header_offset = synthesize_yaral_rule(rule)
        response = self._client.request(
            "POST",
            ":verifyRuleText",
            body={"ruleText": rule_text},
        )
        return self._parse_response(response, header_offset=header_offset, rule_text=rule_text)

    def _parse_response(
        self,
        response: dict[str, object],
        header_offset: int,
        rule_text: str,
    ) -> CompilationResult:
        success = bool(response.get("success", False))
        diagnostics_raw = response.get("compilationDiagnostics")

        diagnostics: list[CompilationDiagnostic] = []
        if isinstance(diagnostics_raw, list):
            for item in diagnostics_raw:
                if isinstance(item, dict):
                    line = _parse_int_field(item.get("startLine", item.get("line", 1)))
                    column = _parse_int_field(item.get("startColumn", item.get("column", 1)))
                    message = str(item.get("message", "Compilation error"))
                    severity = str(item.get("severity", "ERROR"))

                    translated_line = max(1, line - header_offset) if header_offset > 0 else line

                    diagnostics.append(
                        CompilationDiagnostic(
                            line=translated_line,
                            column=column,
                            message=message,
                            severity=severity,
                        )
                    )

        raw_response: dict[str, object] = {
            **response,
            "synthesized_rule_text": rule_text,
            "header_offset": header_offset,
        }

        return CompilationResult(
            success=success,
            diagnostics=tuple(diagnostics),
            raw_response=raw_response,
        )

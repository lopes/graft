import dataclasses
import re
import textwrap
import uuid
from pathlib import Path

from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.rule import RuleEnvelope, RuleMetadata
from graft.core.ports.compiler import RuleCompilerPort
from graft.engines.secops.client import SecOpsClient

_UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_RULE_HEADER_REGEX = re.compile(r"^\s*rule\s+([a-zA-Z0-9_]+)\s*\{", re.MULTILINE)
_SECTION_HEADER_REGEX = re.compile(r"^\s*(events|match|condition):", re.MULTILINE)
_MISSING_DATATABLE_DIAG_RE = re.compile(
    r"data\s+table\s+(?:\(\s*(?P<paren>[a-zA-Z0-9_]+)\s*\)|%(?P<pct>[a-zA-Z0-9_]+))",
    re.IGNORECASE,
)


def _sanitize_slug(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", raw).strip("_").lower()
    cleaned = cleaned[:64].rstrip("_")
    if cleaned == "index":
        return "index_rule"
    return cleaned or "unnamed_rule"


def _extract_uuid(candidate: str, fallback: str) -> str:
    cleaned_cand = candidate.strip().strip('"').strip("'")
    if cleaned_cand.startswith("ru_"):
        cleaned_cand = cleaned_cand[3:]
    if _UUID_REGEX.match(cleaned_cand):
        return cleaned_cand

    cleaned_fb = fallback.strip()
    if cleaned_fb.startswith("ru_"):
        cleaned_fb = cleaned_fb[3:]
    if _UUID_REGEX.match(cleaned_fb):
        return cleaned_fb

    seed = candidate.strip() or fallback.strip() or "rule"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


def _indent_logic(logic: str, indent: str = "  ") -> str:
    lines = logic.strip().splitlines()
    return "\n".join(indent + line if line.strip() else "" for line in lines)


def synthesize_yaral_rule(rule: RuleEnvelope) -> tuple[str, int]:
    meta_id = rule.metadata.id
    meta_desc = rule.metadata.description.replace('"', '\\"')

    header_lines = [
        f"rule {rule.metadata.name} {{",
        "  meta:",
        f'    id = "{meta_id}"',
        f'    description = "{meta_desc}"',
    ]
    header_offset = len(header_lines)
    rule_text = "\n".join(header_lines) + "\n" + _indent_logic(rule.logic) + "\n}\n"
    return rule_text, header_offset


def deconstruct_yaral_rule(
    rule_text: str,
    fallback_id: str = "",
    fallback_name: str = "",
) -> tuple[RuleMetadata, str]:
    rule_match = _RULE_HEADER_REGEX.search(rule_text)
    if not rule_match:
        rule_name = _sanitize_slug(fallback_name)
        rule_id = _extract_uuid(fallback_id, fallback_name)
        metadata = RuleMetadata(
            id=rule_id,
            name=rule_name,
            description=f"Imported detection rule for {rule_name}"[:128],
            owners=(),
            mitre={},
        )
        return metadata, rule_text.strip()

    rule_name = _sanitize_slug(rule_match.group(1))
    meta_dict: dict[str, str] = {}

    meta_start = re.search(r"^\s*meta:\s*$", rule_text, re.MULTILINE)
    body_start_pos = 0

    if meta_start:
        start_idx = meta_start.end()
        next_sec = _SECTION_HEADER_REGEX.search(rule_text, pos=start_idx)
        if next_sec:
            meta_content = rule_text[start_idx : next_sec.start()]
            body_start_pos = next_sec.start()
        else:
            end_brace = rule_text.rfind("}")
            meta_content = (
                rule_text[start_idx:end_brace] if end_brace != -1 else rule_text[start_idx:]
            )
            body_start_pos = end_brace if end_brace != -1 else len(rule_text)

        for line in meta_content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue
            kv = re.match(r"^([a-zA-Z0-9_]+)\s*=\s*(.*)$", stripped)
            if kv:
                k = kv.group(1).lower()
                val = kv.group(2).strip().strip('"').strip("'")
                meta_dict[k] = val
    else:
        first_sec = _SECTION_HEADER_REGEX.search(rule_text, pos=rule_match.end())
        body_start_pos = first_sec.start() if first_sec else rule_match.end()

    last_brace = rule_text.rfind("}")
    if last_brace > body_start_pos:
        logic_body = rule_text[body_start_pos:last_brace]
    else:
        logic_body = rule_text[body_start_pos:]

    logic_body = textwrap.dedent(logic_body.lstrip("\r\n")).strip()

    meta_id = _extract_uuid(meta_dict.get("id", ""), fallback_id or rule_name)
    desc = meta_dict.get("description", f"Imported detection rule for {rule_name}")
    if len(desc) > 128:
        desc = desc[:125] + "..."
    metadata = RuleMetadata(
        id=meta_id,
        name=rule_name,
        description=desc,
        owners=(),
        mitre={},
    )
    return metadata, logic_body


def extract_meta_id(rule_text: str) -> str | None:
    meta_start = re.search(r"^\s*meta:\s*$", rule_text, re.MULTILINE)
    if not meta_start:
        return None
    start_idx = meta_start.end()
    next_sec = _SECTION_HEADER_REGEX.search(rule_text, pos=start_idx)
    end_idx = next_sec.start() if next_sec else rule_text.rfind("}")
    meta_content = rule_text[start_idx:end_idx] if end_idx != -1 else rule_text[start_idx:]
    for line in meta_content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue
        kv = re.match(r"^([a-zA-Z0-9_]+)\s*=\s*(.*)$", stripped)
        if kv and kv.group(1).lower() == "id":
            val = kv.group(2).strip().strip('"').strip("'")
            if val:
                return val
    return None


def _parse_int_field(value: object, default: int = 1) -> int:
    if isinstance(value, (int, str)) and str(value).isdigit():
        return int(str(value))
    return default


class SecOpsCompilerAdapter(RuleCompilerPort):
    def __init__(self, client: SecOpsClient) -> None:
        self._client = client

    def verify_syntax(self, rule_text: str) -> CompilationResult:
        rule_match = _RULE_HEADER_REGEX.search(rule_text)
        if rule_match:
            final_text = rule_text
            header_offset = 0
        else:
            header_lines = [
                "rule verify_syntax_rule {",
                "  meta:",
                '    id = "00000000-0000-0000-0000-000000000000"',
            ]
            header_offset = len(header_lines)
            final_text = "\n".join(header_lines) + "\n" + _indent_logic(rule_text) + "\n}\n"

        response = self._client.request(
            "POST",
            ":verifyRuleText",
            body={"ruleText": final_text},
        )
        return self._parse_response(response, header_offset=header_offset, rule_text=final_text)

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        rule_text, header_offset = synthesize_yaral_rule(rule)
        response = self._client.request(
            "POST",
            ":verifyRuleText",
            body={"ruleText": rule_text},
        )
        result = self._parse_response(response, header_offset=header_offset, rule_text=rule_text)
        if result.success or not result.diagnostics:
            return result

        missing_local_tables: set[str] = set()
        for diag in result.diagnostics:
            for match in _MISSING_DATATABLE_DIAG_RE.finditer(diag.message):
                ds_name = match.group("paren") or match.group("pct")
                if ds_name and (
                    (Path("datasets") / f"{ds_name}.yaml").is_file()
                    or (Path("datasets") / f"{ds_name}.yml").is_file()
                ):
                    missing_local_tables.add(ds_name)

        if not missing_local_tables:
            return result

        substituted_logic = rule.logic
        for ds_name in sorted(missing_local_tables):
            substituted_logic = re.sub(
                rf"\bin\s+%{re.escape(ds_name)}\.value\b",
                '= "graft_verify_placeholder"',
                substituted_logic,
            )
            substituted_logic = re.sub(
                rf"%{re.escape(ds_name)}\.value\b",
                '"graft_verify_placeholder"',
                substituted_logic,
            )

        if substituted_logic == rule.logic:
            return result

        sub_rule = dataclasses.replace(rule, logic=substituted_logic)
        sub_text, sub_offset = synthesize_yaral_rule(sub_rule)
        sub_response = self._client.request(
            "POST",
            ":verifyRuleText",
            body={"ruleText": sub_text},
        )
        return self._parse_response(sub_response, header_offset=sub_offset, rule_text=sub_text)

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

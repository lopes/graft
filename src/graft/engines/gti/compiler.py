from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.rule import RuleEnvelope, RuleMetadata
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.validation.mitre_validator import get_default_mitre_validator
from graft.engines.gti.client import GTIApiError, GTIClient

logger = logging.getLogger("graft.gti.compiler")

_YARA_IMPORT_LINE_RE = re.compile(r'^\s*import\s+"([a-zA-Z0-9_]+)"\s*$')
_YARA_RULE_WRAPPER_RE = re.compile(
    r"^\s*rule\s+([a-zA-Z0-9_]+)\s*\{\s*(.*?)\s*\}\s*$",
    re.DOTALL,
)
_DATASET_TOKEN_RE = re.compile(r"%([a-zA-Z_][a-zA-Z0-9_]*)(?:\.([a-zA-Z_][a-zA-Z0-9_]*))?")
_META_KEY_VAL_RE = re.compile(r'^\s*([a-zA-Z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')
_GTI_LINE_ERR_RE = re.compile(r"\bline\s+(\d+)\s*:", re.IGNORECASE)

_VALID_SUBTYPES = frozenset({"file", "url", "domain", "ip_address"})

_GRAFT_MANAGED_META_KEYS = frozenset(
    {
        "graft_id",
        "description",
        "owners",
        "mitre_tactic",
        "mitre_technique",
    }
)


def _escape_yara_str(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


def _unescape_yara_str(val: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(val):
        if val[i] == "\\" and i + 1 < len(val):
            nxt = val[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == '"':
                out.append('"')
            elif nxt == "\\":
                out.append("\\")
            else:
                out.append(nxt)
            i += 2
        else:
            out.append(val[i])
            i += 1
    return "".join(out)


def _strip_quoted_strings_and_comments(text: str) -> str:
    cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"//[^\n]*", "", cleaned)
    return cleaned


def validate_gti_dataset_references(
    rule: RuleEnvelope,
    local_dataset_names: set[str],
) -> None:
    stripped = _strip_quoted_strings_and_comments(rule.logic)
    for match in _DATASET_TOKEN_RE.finditer(stripped):
        ds_name = match.group(1)
        col_name = match.group(2)
        if col_name is not None or ds_name in local_dataset_names or ds_name == "index":
            ref_str = f"%{ds_name}.{col_name}" if col_name else f"%{ds_name}"
            raise ValueError(
                f"Rule '{rule.metadata.name}' references dataset '{ref_str}': "
                "Google Threat Intelligence (gti) does not support dataset lookup tables; "
                "write native YARA-X conditions directly"
            )


def _partition_imports_and_body(raw_logic: str) -> tuple[list[str], str]:
    lines = raw_logic.strip().splitlines()
    imports: list[str] = []
    seen_imports: set[str] = set()
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue
        m = _YARA_IMPORT_LINE_RE.match(stripped)
        if m:
            mod_name = m.group(1)
            stmt = f'import "{mod_name}"'
            if stmt not in seen_imports:
                seen_imports.add(stmt)
                imports.append(stmt)
            idx += 1
            continue
        break

    remainder = "\n".join(lines[idx:]).strip()
    wrapper_match = _YARA_RULE_WRAPPER_RE.match(remainder)
    if wrapper_match:
        remainder = wrapper_match.group(2).strip()

    return imports, remainder


def _strip_existing_graft_meta(body: str) -> tuple[dict[str, str], str]:
    extracted_meta: dict[str, str] = {}
    lines = body.splitlines()
    out_lines: list[str] = []
    in_meta = False
    user_meta_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not in_meta and stripped == "meta:":
            in_meta = True
            continue
        if in_meta:
            if stripped in ("strings:", "condition:") or re.match(
                r"^(strings|condition)\s*:", stripped
            ):
                in_meta = False
                if user_meta_lines:
                    out_lines.append("  meta:")
                    out_lines.extend(user_meta_lines)
                out_lines.append(line)
                continue
            if not stripped:
                continue
            kv = _META_KEY_VAL_RE.match(stripped)
            if kv:
                k, v = kv.group(1), _unescape_yara_str(kv.group(2))
                if k in _GRAFT_MANAGED_META_KEYS:
                    extracted_meta[k] = v
                else:
                    user_meta_lines.append(f"    {stripped}")
            else:
                user_meta_lines.append(f"    {stripped}")
        else:
            out_lines.append(line)

    if in_meta and user_meta_lines:
        out_lines.append("  meta:")
        out_lines.extend(user_meta_lines)

    dedented: list[str] = []
    non_empty_indents = [len(ln) - len(ln.lstrip(" ")) for ln in out_lines if ln.strip()]
    min_indent = min(non_empty_indents) if non_empty_indents else 0
    for ln in out_lines:
        if ln.strip() and len(ln) >= min_indent:
            dedented.append(ln[min_indent:])
        else:
            dedented.append(ln.strip())

    return extracted_meta, "\n".join(dedented).strip()


def resolve_gti_subtype(rule: RuleEnvelope) -> str:
    dep_type = rule.deployment.get("type")
    if dep_type not in ("livehunt", "retrohunt"):
        raise ValueError(
            f"Rule '{rule.metadata.name}' has invalid or missing deployment.type "
            f"'{dep_type}'; expected 'livehunt' or 'retrohunt'"
        )
    if dep_type == "retrohunt":
        return "file"
    subtype = rule.deployment.get("subtype")
    if isinstance(subtype, str) and subtype in _VALID_SUBTYPES:
        return subtype
    raise ValueError(
        f"Rule '{rule.metadata.name}' has invalid or missing deployment.subtype "
        f"'{subtype}'; Livehunt rules require one of {sorted(_VALID_SUBTYPES)}"
    )


def synthesize_yara_rule(rule: RuleEnvelope) -> tuple[str, int]:
    imports, raw_body = _partition_imports_and_body(rule.logic)
    _, cleaned_body = _strip_existing_graft_meta(raw_body)

    meta_lines: list[str] = ["  meta:"]
    if rule.metadata.id:
        meta_lines.append(f'    graft_id = "{_escape_yara_str(rule.metadata.id)}"')
    if rule.metadata.description:
        meta_lines.append(f'    description = "{_escape_yara_str(rule.metadata.description)}"')
    if rule.metadata.owners:
        owners_str = ", ".join(rule.metadata.owners)
        meta_lines.append(f'    owners = "{_escape_yara_str(owners_str)}"')
    if rule.metadata.mitre:
        tactics = list(rule.metadata.mitre.keys())
        techniques: list[str] = []
        for t_list in rule.metadata.mitre.values():
            for tech in t_list:
                if tech not in techniques:
                    techniques.append(tech)
        if tactics:
            meta_lines.append(f'    mitre_tactic = "{_escape_yara_str(", ".join(tactics))}"')
        if techniques:
            meta_lines.append(f'    mitre_technique = "{_escape_yara_str(", ".join(techniques))}"')

    prefix_lines: list[str] = []
    if imports:
        prefix_lines.extend(imports)
        prefix_lines.append("")
    prefix_lines.append(f"rule {rule.metadata.name} {{")
    prefix_lines.extend(meta_lines)
    prefix_lines.append("")

    # header_offset maps synthesized body start line back to rule.logic lines
    import_line_count = len(imports) + (1 if imports else 0)
    header_offset = len(prefix_lines) - import_line_count

    indented_body_lines = [f"  {ln}" if ln.strip() else "" for ln in cleaned_body.splitlines()]
    full_lines = [*prefix_lines, *indented_body_lines, "}"]
    return "\n".join(full_lines), max(0, header_offset)


def deconstruct_yara_rule(remote_rule: RuleEnvelope) -> RuleEnvelope:
    imports, raw_body = _partition_imports_and_body(remote_rule.logic)
    extracted_meta, cleaned_body = _strip_existing_graft_meta(raw_body)

    wrapper_match = _YARA_RULE_WRAPPER_RE.match(
        "\n".join(
            ln
            for ln in remote_rule.logic.strip().splitlines()
            if not _YARA_IMPORT_LINE_RE.match(ln.strip())
        ).strip()
    )
    inferred_name = wrapper_match.group(1) if wrapper_match else remote_rule.metadata.name

    rule_id = extracted_meta.get("graft_id") or remote_rule.metadata.id
    description = extracted_meta.get("description") or remote_rule.metadata.description
    owners: tuple[str, ...] = remote_rule.metadata.owners
    if "owners" in extracted_meta:
        owners = tuple(o.strip() for o in extracted_meta["owners"].split(",") if o.strip())

    mitre_map = dict(remote_rule.metadata.mitre)
    raw_tactics = [
        tok.strip() for tok in extracted_meta.get("mitre_tactic", "").split(",") if tok.strip()
    ]
    raw_techniques = [
        tok.strip() for tok in extracted_meta.get("mitre_technique", "").split(",") if tok.strip()
    ]
    if raw_tactics or raw_techniques:
        reconstructed = get_default_mitre_validator().reconstruct_mitre_mapping(
            raw_tactics,
            raw_techniques,
        )
        if reconstructed:
            mitre_map = reconstructed

    recombined_parts: list[str] = []
    if imports:
        recombined_parts.append("\n".join(imports))
    if cleaned_body:
        recombined_parts.append(cleaned_body)
    clean_logic = "\n\n".join(recombined_parts)

    return RuleEnvelope(
        metadata=RuleMetadata(
            id=rule_id,
            name=remote_rule.metadata.name or inferred_name,
            description=description,
            owners=owners,
            mitre=mitre_map,
            tags=remote_rule.metadata.tags,
            references=remote_rule.metadata.references,
        ),
        logic=clean_logic,
        deployment=remote_rule.deployment,
        runbook=remote_rule.runbook,
        tests=remote_rule.tests,
        managed=remote_rule.managed,
    )


class GTICompilerAdapter(RuleCompilerPort):
    def __init__(self, client: GTIClient | None = None) -> None:
        self._client = client

    def _local_syntax_check(self, logic_text: str) -> CompilationDiagnostic | None:
        stripped = logic_text.strip()
        if not stripped:
            return CompilationDiagnostic(
                line=1,
                column=1,
                message="YARA rule logic cannot be empty",
            )
        if "condition:" not in stripped:
            return CompilationDiagnostic(
                line=1,
                column=1,
                message="YARA rule logic is missing a 'condition:' section",
            )
        if stripped.count("{") != stripped.count("}"):
            return CompilationDiagnostic(
                line=1,
                column=1,
                message="Unbalanced braces '{' / '}' in YARA rule logic",
            )
        if stripped.count("(") != stripped.count(")"):
            return CompilationDiagnostic(
                line=1,
                column=1,
                message="Unbalanced parentheses '(' / ')' in YARA rule logic",
            )
        return None

    def verify_syntax(self, rule_text: str) -> CompilationResult:
        from graft.core.models.rule import BaseDeploymentConfig

        temp_rule = RuleEnvelope(
            metadata=RuleMetadata(
                id="00000000-0000-0000-0000-000000000000",
                name="graft_syntax_probe",
                description="Syntax verification probe",
            ),
            logic=rule_text,
            deployment=BaseDeploymentConfig.from_dict(
                {"type": "livehunt", "subtype": "file", "enabled": False}
            ),
        )
        return self.verify_rule(temp_rule)

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        diag = self._local_syntax_check(rule.logic)
        if diag is not None:
            return CompilationResult(success=False, diagnostics=(diag,))

        try:
            match_type = resolve_gti_subtype(rule)
        except ValueError as exc:
            return CompilationResult(
                success=False,
                diagnostics=(CompilationDiagnostic(line=1, column=1, message=str(exc)),),
            )

        yara_text, header_offset = synthesize_yara_rule(rule)

        if self._client is None:
            return CompilationResult(success=True)

        probe_name = f"__graft_verify_{uuid.uuid4().hex[:8]}__"
        payload: dict[str, Any] = {
            "data": {
                "type": "hunting_ruleset",
                "attributes": {
                    "name": probe_name,
                    "rules": yara_text,
                    "enabled": False,
                    "match_object_type": match_type,
                    "limit": 100,
                },
            }
        }

        created_id: str | None = None
        try:
            resp = self._client.post("/intelligence/hunting_rulesets", payload)
            data = resp.get("data", {})
            if isinstance(data, dict) and data.get("id"):
                created_id = str(data["id"])
            return CompilationResult(success=True, raw_response=resp)
        except GTIApiError as exc:
            line_num = 1
            m = _GTI_LINE_ERR_RE.search(str(exc))
            if m:
                raw_line = int(m.group(1))
                line_num = max(1, raw_line - header_offset)
            return CompilationResult(
                success=False,
                diagnostics=(
                    CompilationDiagnostic(
                        line=line_num,
                        column=1,
                        message=str(exc),
                    ),
                ),
            )
        finally:
            if created_id is not None and self._client is not None:
                try:
                    self._client.delete(f"/intelligence/hunting_rulesets/{created_id}")
                except Exception as cleanup_exc:
                    logger.warning(
                        "Failed cleaning up transient verification ruleset '%s': %s",
                        created_id,
                        cleanup_exc,
                    )

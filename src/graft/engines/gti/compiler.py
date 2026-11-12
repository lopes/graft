from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from graft.core.models.compiler import CompilationDiagnostic, CompilationResult
from graft.core.models.rule import RuleEnvelope, RuleMetadata, Runbook
from graft.core.ports.compiler import RuleCompilerPort
from graft.core.validation.mitre_validator import get_default_mitre_validator
from graft.engines.gti.client import GTIApiError, GTIClient, quote_path_segment

logger = logging.getLogger("graft.gti.compiler")

_YARA_IMPORT_LINE_RE = re.compile(r'^\s*import\s+"([a-zA-Z0-9_]+)"\s*$')
_YARA_RULE_WRAPPER_RE = re.compile(
    r"^\s*(?:(?:private|global)\s+)*rule\s+([a-zA-Z0-9_]+)"
    r"(?:\s*:\s*[a-zA-Z0-9_\s]+)?\s*\{\s*(.*?)\s*\}\s*$",
    re.DOTALL,
)
_DATASET_TOKEN_RE = re.compile(
    r"(?<![a-zA-Z0-9_$])%([a-zA-Z_][a-zA-Z0-9_]*)(?:\.([a-zA-Z_][a-zA-Z0-9_]*))?"
)
_YARA_STRING_OR_COMMENT_RE = re.compile(r'"(?:[^"\\]|\\.)*"|/\*[\s\S]*?\*/|//[^\r\n]*')
_META_KEY_VAL_RE = re.compile(r'^\s*([a-zA-Z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')
_GTI_LINE_ERR_RE = re.compile(r"\bline\s+(\d+)\s*:", re.IGNORECASE)
_SNAKE_CASE_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")

_VALID_SUBTYPES = frozenset({"file", "url", "domain", "ip_address"})

_GRAFT_MANAGED_META_KEYS = frozenset(
    {
        "graft_id",
        "description",
        "owners",
        "mitre_tactic",
        "mitre_technique",
        "tags",
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
    return _YARA_STRING_OR_COMMENT_RE.sub(
        lambda m: '""' if m.group(0).startswith('"') else " ",
        text,
    )


def validate_gti_dataset_references(
    rule: RuleEnvelope,
    local_dataset_names: set[str],
) -> None:
    _ = local_dataset_names
    stripped = _strip_quoted_strings_and_comments(rule.logic)
    for match in _DATASET_TOKEN_RE.finditer(stripped):
        ds_name = match.group(1)
        col_name = match.group(2)
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
    body_lines: list[str] = []
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue
        if stripped.startswith("//"):
            body_lines.append(lines[idx])
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

    remainder_lines = [*body_lines, *lines[idx:]]
    uncommented_start = 0
    while uncommented_start < len(remainder_lines):
        st = remainder_lines[uncommented_start].strip()
        if not st or st.startswith("//"):
            uncommented_start += 1
            continue
        break
    candidate = "\n".join(remainder_lines[uncommented_start:]).strip()
    wrapper_match = _YARA_RULE_WRAPPER_RE.match(candidate)
    if wrapper_match:
        remainder = wrapper_match.group(2).strip()
    else:
        remainder = "\n".join(remainder_lines).strip()

    return imports, remainder


def _extract_meta_and_body(body: str) -> tuple[dict[str, str], list[str], str]:
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

    dedented: list[str] = []
    non_empty_indents = [len(ln) - len(ln.lstrip(" ")) for ln in out_lines if ln.strip()]
    min_indent = min(non_empty_indents) if non_empty_indents else 0
    for ln in out_lines:
        if ln.strip() and len(ln) >= min_indent:
            dedented.append(ln[min_indent:])
        else:
            dedented.append(ln.strip())

    return extracted_meta, user_meta_lines, "\n".join(dedented).strip()


def _strip_existing_graft_meta(body: str) -> tuple[dict[str, str], str]:
    extracted_meta, user_meta_lines, clean_body = _extract_meta_and_body(body)
    if user_meta_lines:
        user_meta_block = "\n".join(["meta:", *[f"  {ln.strip()}" for ln in user_meta_lines]])
        combined = f"{user_meta_block}\n\n{clean_body}".strip() if clean_body else user_meta_block
        return extracted_meta, combined
    return extracted_meta, clean_body


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
    _, user_meta_lines, cleaned_body = _extract_meta_and_body(raw_body)

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
    if rule.metadata.tags:
        tags_str = ", ".join(rule.metadata.tags)
        meta_lines.append(f'    tags = "{_escape_yara_str(tags_str)}"')
    if user_meta_lines:
        meta_lines.extend(user_meta_lines)

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


def _normalize_snake_case_name(raw_name: str, fallback: str = "imported_gti_rule") -> str:
    candidate = raw_name.strip()
    cleaned = re.sub(r"[^a-z0-9]+", "_", candidate.lower()).strip("_")
    if cleaned and cleaned[0].isdigit():
        cleaned = f"rule_{cleaned}"
    cleaned = cleaned[:64].rstrip("_")
    if cleaned == "index":
        cleaned = "index_rule"
    if cleaned and _SNAKE_CASE_NAME_RE.match(cleaned):
        return cleaned
    return fallback


def _normalize_tag(raw_tag: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_/:-]+", "-", raw_tag.strip().lower()).strip("-")
    return cleaned[:32]


def deconstruct_yara_rule(remote_rule: RuleEnvelope) -> RuleEnvelope:
    imports, raw_body = _partition_imports_and_body(remote_rule.logic)
    extracted_meta, cleaned_body = _strip_existing_graft_meta(raw_body)

    wrapper_match = _YARA_RULE_WRAPPER_RE.match(
        "\n".join(
            ln
            for ln in remote_rule.logic.strip().splitlines()
            if ln.strip()
            and not ln.strip().startswith("//")
            and not _YARA_IMPORT_LINE_RE.match(ln.strip())
        ).strip()
    )
    inferred_name = wrapper_match.group(1) if wrapper_match else remote_rule.metadata.name
    final_name = _normalize_snake_case_name(
        remote_rule.metadata.name or inferred_name,
        fallback=_normalize_snake_case_name(inferred_name),
    )

    rule_id = extracted_meta.get("graft_id") or remote_rule.metadata.id
    if not rule_id:
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"graft.gti.{final_name}"))

    description = extracted_meta.get("description") or remote_rule.metadata.description
    if not description or len(description.strip()) < 10:
        description = f"Imported GTI detection rule for {final_name}."
    if len(description) > 128:
        description = description[:125].rstrip() + "..."

    owners: tuple[str, ...] = remote_rule.metadata.owners
    if "owners" in extracted_meta:
        owners = tuple(o.strip() for o in extracted_meta["owners"].split(",") if o.strip())
    if not owners:
        owners = ("Detection Engineering",)

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
    if not mitre_map:
        mitre_map = {"none": ("T0000",)}

    raw_tags: tuple[str, ...] = remote_rule.metadata.tags
    if not raw_tags and "tags" in extracted_meta:
        raw_tags = tuple(t.strip() for t in extracted_meta["tags"].split(",") if t.strip())
    normalized_tags = tuple(dict.fromkeys(norm for t in raw_tags if (norm := _normalize_tag(t))))
    if not normalized_tags:
        normalized_tags = ("hunting",)

    references = remote_rule.metadata.references or ("https://gtidocs.virustotal.com/",)

    rb = remote_rule.runbook
    runbook = Runbook(
        context=rb.context
        if rb.context.strip()
        else f"Imported from Google Threat Intelligence for detection {final_name}.",
        triage=rb.triage
        if rb.triage.strip()
        else "1. Inspect matched GTI entity attributes and pivot on related indicators.",
        response=rb.response
        if rb.response.strip()
        else "1. Follow organizational threat hunting and incident response playbooks.",
    )

    recombined_parts: list[str] = []
    if imports:
        recombined_parts.append("\n".join(imports))
    if cleaned_body:
        recombined_parts.append(cleaned_body)
    clean_logic = "\n\n".join(recombined_parts)

    return RuleEnvelope(
        metadata=RuleMetadata(
            id=rule_id,
            name=final_name,
            description=description,
            owners=owners,
            mitre=mitre_map,
            tags=normalized_tags,
            references=references,
        ),
        logic=clean_logic,
        deployment=remote_rule.deployment,
        runbook=runbook,
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
        code_only = _strip_quoted_strings_and_comments(stripped)
        if "condition:" not in code_only:
            return CompilationDiagnostic(
                line=1,
                column=1,
                message="YARA rule logic is missing a 'condition:' section",
            )
        if code_only.count("{") != code_only.count("}"):
            return CompilationDiagnostic(
                line=1,
                column=1,
                message="Unbalanced braces '{' / '}' in YARA rule logic",
            )
        if code_only.count("(") != code_only.count(")"):
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

    def _validate_retrohunt_time_range(self, rule: RuleEnvelope) -> None:
        if rule.deployment.get("type") != "retrohunt":
            return
        start_val = rule.deployment.get("start_time")
        end_val = rule.deployment.get("end_time")
        start_ts: int | None = None
        end_ts: int | None = None
        if isinstance(start_val, str) and start_val.strip():
            norm = start_val.strip()
            if norm.endswith("Z"):
                norm = norm[:-1] + "+00:00"
            dt = datetime.fromisoformat(norm)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            start_ts = int(dt.timestamp())
        if isinstance(end_val, str) and end_val.strip():
            norm = end_val.strip()
            if norm.endswith("Z"):
                norm = norm[:-1] + "+00:00"
            dt = datetime.fromisoformat(norm)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            end_ts = int(dt.timestamp())
        if start_ts is not None and end_ts is not None and start_ts >= end_ts:
            raise ValueError(
                f"Rule '{rule.metadata.name}' has invalid Retrohunt time range: "
                "deployment.start_time must be earlier than deployment.end_time"
            )

    def verify_rule(self, rule: RuleEnvelope) -> CompilationResult:
        diag = self._local_syntax_check(rule.logic)
        if diag is not None:
            return CompilationResult(success=False, diagnostics=(diag,))

        try:
            match_type = resolve_gti_subtype(rule)
            self._validate_retrohunt_time_range(rule)
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
                    safe_id = quote_path_segment(created_id)
                    self._client.delete(f"/intelligence/hunting_rulesets/{safe_id}")
                except Exception as cleanup_exc:
                    logger.warning(
                        "Failed cleaning up transient verification ruleset '%s': %s",
                        created_id,
                        cleanup_exc,
                    )

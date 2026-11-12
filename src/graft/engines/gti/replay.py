from __future__ import annotations

import ast
import logging
import re
import time
from collections.abc import Mapping
from typing import Any

from graft.core.models.rule import RuleEnvelope, TestVector
from graft.core.ports.replay import ReplayHarnessPort, ReplayResult
from graft.engines.gti.client import GTIApiError, GTIClient, quote_path_segment
from graft.engines.gti.compiler import (
    _extract_meta_and_body,
    _partition_imports_and_body,
    _unescape_yara_str,
    synthesize_yara_rule,
)

logger = logging.getLogger("graft.gti.replay")

_STRING_DEF_RE = re.compile(r'^\s*(\$[a-zA-Z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"(.*)$')
_REGEX_DEF_RE = re.compile(r"^\s*(\$[a-zA-Z0-9_]+)\s*=\s*/((?:[^/\\]|\\.)*)/([a-zA-Z]*)(.*)$")
_CMP_OP_RE = re.compile(
    r"(?<![a-zA-Z0-9_.$])([a-zA-Z0-9_.]+|-?\d+)\s+"
    r"(icontains|contains|istartswith|startswith|iendswith|endswith|iequals|matches|==|!=|<=|>=|<|>)\s+"
    r'("(?:[^"\\]|\\.)*"|/(?:[^/\\]|\\.)*/[a-zA-Z]*|-?\d+(?:KB|MB|GB)?\b|[a-zA-Z0-9_.]+)'
)
_SIZE_LITERAL_RE = re.compile(r"^(-?\d+)(KB|MB|GB)?$", re.IGNORECASE)
_FOR_HEADER_RE = re.compile(
    r"\bfor\s+(any|all)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+in\s+([a-zA-Z0-9_.]+)\s*:\s*\("
)
_DEFINED_PAREN_RE = re.compile(r"\bdefined\s*\(\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\)")
_DEFINED_BARE_RE = re.compile(r"\bdefined\s+([a-zA-Z_][a-zA-Z0-9_.]*)\b")
_QUANTIFIER_OF_RE = re.compile(
    r"\b(any|all|\d+)\s+of\s+(them|\(\s*\$[a-zA-Z0-9_*]+(?:\s*,\s*\$[a-zA-Z0-9_*]+)*\s*\))"
)
_COUNT_VAR_RE = re.compile(r"#([a-zA-Z0-9_]+)\b")
_ARITH_SUM_PAREN_RE = re.compile(r"\(\s*(\d+(?:\s*\+\s*\d+)+)\s*\)")
_ARITH_SUM_BARE_RE = re.compile(r"\b(\d+(?:\s*\+\s*\d+)+)\b")


class _StringSpec:
    def __init__(
        self,
        pattern: str,
        *,
        is_regex: bool,
        nocase: bool,
        fullword: bool,
    ) -> None:
        self.pattern = pattern
        self.is_regex = is_regex
        self.nocase = nocase
        self.fullword = fullword


def _parse_string_def_line(line: str) -> tuple[str, _StringSpec] | None:
    m_str = _STRING_DEF_RE.match(line)
    if m_str:
        mods = m_str.group(3).lower()
        return (
            m_str.group(1),
            _StringSpec(
                _unescape_yara_str(m_str.group(2)),
                is_regex=False,
                nocase="nocase" in mods,
                fullword="fullword" in mods,
            ),
        )
    m_re = _REGEX_DEF_RE.match(line)
    if m_re:
        flags = m_re.group(3).lower()
        mods = m_re.group(4).lower()
        return (
            m_re.group(1),
            _StringSpec(
                m_re.group(2),
                is_regex=True,
                nocase=("i" in flags) or ("nocase" in mods),
                fullword="fullword" in mods,
            ),
        )
    return None


def _extract_strings_and_condition(
    rule: RuleEnvelope,
) -> tuple[dict[str, _StringSpec], str]:
    _, raw_body = _partition_imports_and_body(rule.logic)
    _, _, cleaned_body = _extract_meta_and_body(raw_body)

    string_defs: dict[str, _StringSpec] = {}
    cond_lines: list[str] = []
    section: str | None = None

    for line in cleaned_body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped == "strings:" or stripped.startswith("strings:"):
            section = "strings"
            after = stripped[len("strings:") :].strip()
            if after:
                parsed = _parse_string_def_line(after)
                if parsed:
                    string_defs[parsed[0]] = parsed[1]
            continue
        if stripped == "condition:" or stripped.startswith("condition:"):
            section = "condition"
            after = stripped[len("condition:") :].strip()
            if after:
                cond_lines.append(after)
            continue

        if section == "strings":
            parsed = _parse_string_def_line(stripped)
            if parsed:
                string_defs[parsed[0]] = parsed[1]
        elif section == "condition":
            cond_lines.append(stripped)

    return string_defs, " ".join(cond_lines).strip()


def _lookup_field(payload: Mapping[str, object], field_path: str) -> object:
    if field_path in payload:
        return payload[field_path]
    curr: object = payload
    for part in field_path.split("."):
        if isinstance(curr, Mapping) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr


def _parse_literal(token: str, payload: Mapping[str, object]) -> object:
    tok = token.strip()
    if len(tok) >= 2 and tok.startswith('"') and tok.endswith('"'):
        return _unescape_yara_str(tok[1:-1])
    if tok.lower() == "true":
        return True
    if tok.lower() == "false":
        return False
    m_size = _SIZE_LITERAL_RE.match(tok)
    if m_size:
        val = int(m_size.group(1))
        unit = (m_size.group(2) or "").upper()
        if unit == "KB":
            return val * 1024
        if unit == "MB":
            return val * 1024 * 1024
        if unit == "GB":
            return val * 1024 * 1024 * 1024
        return val
    looked_up = _lookup_field(payload, tok)
    if looked_up is not None:
        return looked_up
    return tok


def _count_string_matches(
    var_name: str,
    spec: _StringSpec,
    sample_text: str,
    payload: Mapping[str, object],
) -> int:
    count_key = f"#{var_name[1:]}"
    if count_key in payload:
        raw_cnt = payload[count_key]
        if isinstance(raw_cnt, (int, float)) and not isinstance(raw_cnt, bool):
            return int(raw_cnt)
    if var_name in payload:
        raw_val = payload[var_name]
        if isinstance(raw_val, (int, float)) and not isinstance(raw_val, bool):
            return int(raw_val)
        return 1 if bool(raw_val) else 0

    flags = re.IGNORECASE if spec.nocase else 0
    if spec.is_regex:
        return len(re.findall(spec.pattern, sample_text, flags=flags))
    if spec.fullword:
        return len(re.findall(rf"\b{re.escape(spec.pattern)}\b", sample_text, flags=flags))
    if not spec.pattern:
        return 0
    if spec.nocase:
        return sample_text.lower().count(spec.pattern.lower())
    return sample_text.count(spec.pattern)


def _find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    in_quote = False
    in_regex = False
    escaped = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_quote:
            if ch == '"':
                in_quote = False
            continue
        if in_regex:
            if ch == "/":
                in_regex = False
            continue
        if ch == '"':
            in_quote = True
            continue
        if ch == "/":
            prev = text[:idx].rstrip()
            if prev.endswith("matches") or prev.endswith("("):
                in_regex = True
                continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _expand_for_loops(
    string_defs: Mapping[str, _StringSpec],
    expr: str,
    payload: Mapping[str, object],
) -> str:
    while True:
        m = _FOR_HEADER_RE.search(expr)
        if not m:
            break
        quantifier = m.group(1)
        loop_var = m.group(2)
        collection_path = m.group(3)
        open_paren_idx = m.end() - 1
        close_paren_idx = _find_matching_paren(expr, open_paren_idx)
        if close_paren_idx == -1:
            break

        inner_expr = expr[open_paren_idx + 1 : close_paren_idx]
        collection_obj = _lookup_field(payload, collection_path)
        items: list[object] = (
            list(collection_obj) if isinstance(collection_obj, (list, tuple)) else []
        )

        if not items:
            loop_result = False
        else:
            outcomes: list[bool] = []
            for item in items:
                child_payload = dict(payload)
                child_payload[loop_var] = item
                if isinstance(item, Mapping):
                    for k, v in item.items():
                        child_payload[f"{loop_var}.{k}"] = v
                outcomes.append(
                    _evaluate_condition_against_payload(string_defs, inner_expr, child_payload)
                )
            loop_result = any(outcomes) if quantifier == "any" else all(outcomes)

        expr = (
            expr[: m.start()] + ("True" if loop_result else "False") + expr[close_paren_idx + 1 :]
        )
    return expr


def _evaluate_condition_against_payload(
    string_defs: Mapping[str, _StringSpec],
    condition_expr: str,
    payload: Mapping[str, object],
) -> bool:
    if not condition_expr:
        return False
    if condition_expr.strip().lower() == "true":
        return True
    if condition_expr.strip().lower() == "false":
        return False

    sample_text = str(payload.get("sample_text", ""))
    expr = _expand_for_loops(string_defs, condition_expr, payload)

    string_counts: dict[str, int] = {
        var_name: _count_string_matches(var_name, spec, sample_text, payload)
        for var_name, spec in string_defs.items()
    }

    def _eval_quantifier_of(match: re.Match[str]) -> str:
        quant = match.group(1)
        target = match.group(2).strip()
        if target == "them":
            candidate_vars = list(string_defs.keys())
        else:
            inner = target[1:-1]
            patterns = [p.strip() for p in inner.split(",") if p.strip()]
            candidate_vars = []
            for var_name in string_defs:
                for pat in patterns:
                    if pat.endswith("*"):
                        if var_name.startswith(pat[:-1]):
                            candidate_vars.append(var_name)
                            break
                    elif var_name == pat:
                        candidate_vars.append(var_name)
                        break
        matched_count = sum(1 for v in candidate_vars if string_counts.get(v, 0) > 0)
        if quant == "any":
            return "True" if matched_count >= 1 else "False"
        if quant == "all":
            return (
                "True"
                if (len(candidate_vars) > 0 and matched_count == len(candidate_vars))
                else "False"
            )
        return "True" if matched_count >= int(quant) else "False"

    expr = _QUANTIFIER_OF_RE.sub(_eval_quantifier_of, expr)

    def _eval_count_var(match: re.Match[str]) -> str:
        var_name = f"${match.group(1)}"
        return str(string_counts.get(var_name, 0))

    expr = _COUNT_VAR_RE.sub(_eval_count_var, expr)

    def _eval_arith_sum(match: re.Match[str]) -> str:
        parts = [int(p.strip()) for p in match.group(1).split("+")]
        return str(sum(parts))

    expr = _ARITH_SUM_PAREN_RE.sub(_eval_arith_sum, expr)
    expr = _ARITH_SUM_BARE_RE.sub(_eval_arith_sum, expr)

    for var_name in sorted(string_defs.keys(), key=len, reverse=True):
        matched = string_counts.get(var_name, 0) > 0
        expr = re.sub(
            rf"{re.escape(var_name)}\b",
            "True" if matched else "False",
            expr,
        )

    def _eval_defined(match: re.Match[str]) -> str:
        field_name = match.group(1)
        return "True" if _lookup_field(payload, field_name) is not None else "False"

    expr = _DEFINED_PAREN_RE.sub(_eval_defined, expr)
    expr = _DEFINED_BARE_RE.sub(_eval_defined, expr)

    def _eval_cmp(match: re.Match[str]) -> str:
        lhs_name = match.group(1)
        op = match.group(2)
        rhs_tok = match.group(3)
        lhs_val = (
            int(lhs_name) if re.match(r"^-?\d+$", lhs_name) else _lookup_field(payload, lhs_name)
        )

        if lhs_val is None:
            return "False"

        if op == "matches" and rhs_tok.startswith("/"):
            last_slash = rhs_tok.rfind("/")
            pattern = rhs_tok[1:last_slash]
            flags_str = rhs_tok[last_slash + 1 :].lower()
            flags = re.IGNORECASE if "i" in flags_str else 0
            if "s" in flags_str:
                flags |= re.DOTALL
            return "True" if re.search(pattern, str(lhs_val), flags=flags) is not None else "False"

        rhs_val = _parse_literal(rhs_tok, payload)
        if op == "==":
            return "True" if str(lhs_val) == str(rhs_val) else "False"
        if op == "!=":
            return "True" if str(lhs_val) != str(rhs_val) else "False"
        if op == "iequals":
            return "True" if str(lhs_val).lower() == str(rhs_val).lower() else "False"
        if op in ("<", "<=", ">", ">="):
            try:
                l_num = float(str(lhs_val))
                r_num = float(str(rhs_val))
            except ValueError:
                return "False"
            if op == "<":
                return "True" if l_num < r_num else "False"
            if op == "<=":
                return "True" if l_num <= r_num else "False"
            if op == ">":
                return "True" if l_num > r_num else "False"
            return "True" if l_num >= r_num else "False"
        if op == "icontains":
            return "True" if str(rhs_val).lower() in str(lhs_val).lower() else "False"
        if op == "contains":
            return "True" if str(rhs_val) in str(lhs_val) else "False"
        if op == "startswith":
            return "True" if str(lhs_val).startswith(str(rhs_val)) else "False"
        if op == "istartswith":
            return "True" if str(lhs_val).lower().startswith(str(rhs_val).lower()) else "False"
        if op == "endswith":
            return "True" if str(lhs_val).endswith(str(rhs_val)) else "False"
        if op == "iendswith":
            return "True" if str(lhs_val).lower().endswith(str(rhs_val).lower()) else "False"
        if op == "matches":
            return "True" if re.search(str(rhs_val), str(lhs_val)) is not None else "False"
        return "False"

    expr = _CMP_OP_RE.sub(_eval_cmp, expr)

    def _eval_ident(match: re.Match[str]) -> str:
        tok = match.group(0)
        if tok in ("and", "or", "not", "True", "False"):
            return tok
        val = _lookup_field(payload, tok)
        return "True" if bool(val) else "False"

    expr = re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_.]*\b", _eval_ident, expr)

    return _safe_eval_bool_ast(expr)


def _safe_eval_bool_ast(expr: str) -> bool:
    tree = ast.parse(expr.strip(), mode="eval")

    def _eval_node(node: ast.AST) -> bool:
        if isinstance(node, ast.Expression):
            return _eval_node(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not _eval_node(node.operand)
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(_eval_node(v) for v in node.values)
            if isinstance(node.op, ast.Or):
                return any(_eval_node(v) for v in node.values)
        raise ValueError(f"Unsupported boolean expression node in YARA condition: {ast.dump(node)}")

    return _eval_node(tree)


class GTIReplayAdapter(ReplayHarnessPort):
    def __init__(
        self,
        client: GTIClient | None = None,
        poll_interval_seconds: float = 2.0,
        max_poll_attempts: int = 15,
    ) -> None:
        self._client = client
        self._poll_interval_seconds = poll_interval_seconds
        self._max_poll_attempts = max_poll_attempts
        self.unavailable_reason: str | None = None

    def is_available(self) -> bool:
        return True

    def _run_retrohunt_vector(
        self,
        rule: RuleEnvelope,
        vector: TestVector,
        event_payload: Mapping[str, object],
    ) -> ReplayResult:
        if self._client is None:
            reason = "Retrohunt test vector requires GTI API credentials (GRAFT_GTI_API_KEY)"
            self.unavailable_reason = reason
            return ReplayResult(
                test_id=vector.id,
                passed=False,
                message=reason,
                matched_events_count=0,
            )

        yara_text, _ = synthesize_yara_rule(rule)
        corpus = str(event_payload.get("corpus", "main"))
        attrs: dict[str, Any] = {
            "rules": yara_text,
            "corpus": corpus,
        }
        tr = event_payload.get("time_range")
        if isinstance(tr, Mapping):
            attrs["time_range"] = dict(tr)

        job_id: str | None = None
        try:
            resp = self._client.post(
                "/intelligence/retrohunt_jobs",
                {"data": {"type": "retrohunt_job", "attributes": attrs}},
            )
            data = resp.get("data", {})
            if isinstance(data, dict) and data.get("id"):
                job_id = str(data["id"])
            if not job_id:
                return ReplayResult(
                    test_id=vector.id,
                    passed=False,
                    message="GTI Retrohunt API did not return a job ID",
                    matched_events_count=0,
                )

            num_matches = 0
            status = "queued"
            safe_job_id = quote_path_segment(job_id)
            for _ in range(self._max_poll_attempts):
                poll_resp = self._client.get(f"/intelligence/retrohunt_jobs/{safe_job_id}")
                poll_data = poll_resp.get("data", {})
                poll_attrs = poll_data.get("attributes", {}) if isinstance(poll_data, dict) else {}
                if isinstance(poll_attrs, dict):
                    status = str(poll_attrs.get("status") or status)
                    raw_matches = poll_attrs.get("num_matches")
                    if not isinstance(raw_matches, bool) and isinstance(raw_matches, (int, float)):
                        num_matches = int(raw_matches)
                    elif isinstance(raw_matches, str) and raw_matches.strip().isdigit():
                        num_matches = int(raw_matches.strip())
                if status in ("finished", "aborted"):
                    break
                if self._poll_interval_seconds > 0:
                    time.sleep(self._poll_interval_seconds)

            if status != "finished":
                passed = False
                msg = (
                    f"Retrohunt job '{job_id}' ({corpus}) did not finish "
                    f"(status: '{status}', matches: {num_matches}, expected: {vector.expect})"
                )
            else:
                passed = num_matches == vector.expect
                msg = (
                    f"Retrohunt job '{job_id}' ({corpus}) finished with {num_matches} match(es) "
                    f"(expected {vector.expect})"
                )
            return ReplayResult(
                test_id=vector.id,
                passed=passed,
                message=msg,
                matched_events_count=num_matches,
            )
        except GTIApiError as exc:
            return ReplayResult(
                test_id=vector.id,
                passed=False,
                message=str(exc),
                matched_events_count=0,
            )
        finally:
            if job_id is not None and self._client is not None:
                try:
                    safe_job_id = quote_path_segment(job_id)
                    self._client.delete(f"/intelligence/retrohunt_jobs/{safe_job_id}")
                except Exception as cleanup_exc:
                    logger.warning(
                        "Failed deleting transient Retrohunt job '%s': %s",
                        job_id,
                        cleanup_exc,
                    )

    def run_test_vector(
        self,
        rule: RuleEnvelope,
        vector: TestVector,
    ) -> ReplayResult:
        self.unavailable_reason = None
        for ev in vector.events:
            if ev.payload.get("mode") == "retrohunt":
                return self._run_retrohunt_vector(rule, vector, ev.payload)

        try:
            string_defs, cond_expr = _extract_strings_and_condition(rule)
            matched_count = 0
            for ev in vector.events:
                if _evaluate_condition_against_payload(string_defs, cond_expr, ev.payload):
                    matched_count += 1
        except Exception as exc:
            return ReplayResult(
                test_id=vector.id,
                passed=False,
                message=f"Synthetic YARA evaluation error: {exc}",
                matched_events_count=0,
            )

        passed = matched_count == vector.expect
        msg = (
            f"Matched {matched_count} event(s), expected {vector.expect}"
            if passed
            else f"Assertion failed: matched {matched_count} event(s), expected {vector.expect}"
        )
        return ReplayResult(
            test_id=vector.id,
            passed=passed,
            message=msg,
            matched_events_count=matched_count,
        )

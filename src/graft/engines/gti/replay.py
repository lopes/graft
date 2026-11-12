from __future__ import annotations

import ast
import logging
import re
import time
from collections.abc import Mapping
from typing import Any

from graft.core.models.rule import RuleEnvelope, TestVector
from graft.core.ports.replay import ReplayHarnessPort, ReplayResult
from graft.engines.gti.client import GTIApiError, GTIClient
from graft.engines.gti.compiler import (
    _partition_imports_and_body,
    _strip_existing_graft_meta,
    synthesize_yara_rule,
)

logger = logging.getLogger("graft.gti.replay")

_STRING_DEF_RE = re.compile(r'^\s*(\$[a-zA-Z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"(.*)$')
_CMP_OP_RE = re.compile(
    r'\b([a-zA-Z0-9_.]+)\s+(icontains|contains|startswith|endswith|matches|==|!=|<=|>=|<|>)\s+("(?:[^"\\]|\\.)*"|-?\d+|[a-zA-Z0-9_.]+)'
)


def _extract_strings_and_condition(
    rule: RuleEnvelope,
) -> tuple[dict[str, tuple[str, bool]], str]:
    _, raw_body = _partition_imports_and_body(rule.logic)
    _, cleaned_body = _strip_existing_graft_meta(raw_body)

    string_defs: dict[str, tuple[str, bool]] = {}
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
                m = _STRING_DEF_RE.match(after)
                if m:
                    string_defs[m.group(1)] = (
                        m.group(2),
                        "nocase" in m.group(3).lower(),
                    )
            continue
        if stripped == "condition:" or stripped.startswith("condition:"):
            section = "condition"
            after = stripped[len("condition:") :].strip()
            if after:
                cond_lines.append(after)
            continue

        if section == "strings":
            m = _STRING_DEF_RE.match(stripped)
            if m:
                string_defs[m.group(1)] = (
                    m.group(2),
                    "nocase" in m.group(3).lower(),
                )
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
        return tok[1:-1]
    if tok.lower() == "true":
        return True
    if tok.lower() == "false":
        return False
    if re.match(r"^-?\d+$", tok):
        return int(tok)
    looked_up = _lookup_field(payload, tok)
    if looked_up is not None:
        return looked_up
    return tok


def _evaluate_condition_against_payload(
    string_defs: Mapping[str, tuple[str, bool]],
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
    expr = condition_expr

    # 1. Evaluate $string references
    for var_name in sorted(string_defs.keys(), key=len, reverse=True):
        needle, nocase = string_defs[var_name]
        if var_name in payload:
            matched = bool(payload[var_name])
        elif nocase:
            matched = needle.lower() in sample_text.lower()
        else:
            matched = needle in sample_text
        expr = re.sub(
            rf"{re.escape(var_name)}\b",
            "True" if matched else "False",
            expr,
        )

    # 2. Evaluate binary comparison operators (`icontains`, `contains`, `==`, `!=`, `<`, `>=`, etc.)
    def _eval_cmp(match: re.Match[str]) -> str:
        lhs_name = match.group(1)
        op = match.group(2)
        rhs_tok = match.group(3)
        lhs_val = _lookup_field(payload, lhs_name)
        rhs_val = _parse_literal(rhs_tok, payload)

        if lhs_val is None:
            return "False"
        if op == "==":
            return "True" if str(lhs_val) == str(rhs_val) else "False"
        if op == "!=":
            return "True" if str(lhs_val) != str(rhs_val) else "False"
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
        if op == "endswith":
            return "True" if str(lhs_val).endswith(str(rhs_val)) else "False"
        if op == "matches":
            return "True" if re.search(str(rhs_val), str(lhs_val)) is not None else "False"
        return "False"

    expr = _CMP_OP_RE.sub(_eval_cmp, expr)

    # 3. Replace remaining dotted identifiers (`vt.net.url.new_url`) with boolean truthiness
    def _eval_ident(match: re.Match[str]) -> str:
        tok = match.group(0)
        if tok in ("and", "or", "not", "True", "False"):
            return tok
        val = _lookup_field(payload, tok)
        return "True" if bool(val) else "False"

    expr = re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_.]*\b", _eval_ident, expr)

    return _safe_eval_bool_ast(expr)


def _safe_eval_bool_ast(expr: str) -> bool:
    tree = ast.parse(expr, mode="eval")

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
            for _ in range(self._max_poll_attempts):
                poll_resp = self._client.get(f"/intelligence/retrohunt_jobs/{job_id}")
                poll_data = poll_resp.get("data", {})
                poll_attrs = poll_data.get("attributes", {}) if isinstance(poll_data, dict) else {}
                if isinstance(poll_attrs, dict):
                    status = str(poll_attrs.get("status", status))
                    num_matches = int(poll_attrs.get("num_matches", 0))
                if status in ("finished", "aborted"):
                    break
                if self._poll_interval_seconds > 0:
                    time.sleep(self._poll_interval_seconds)

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
                    self._client.delete(f"/intelligence/retrohunt_jobs/{job_id}")
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

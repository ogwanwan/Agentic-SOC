"""detect/engine.py — Sigma 최소 매칭 엔진 (② 탐지)

정규화 이벤트(공통 스키마 dict) × Rule → seed(common/seed.py). 룰 로드는 detect/loader.py.

지원 범위(의도적으로 최소):
- detection: selection 이름 → dict(모든 키 AND) 또는 list[dict](OR). 값이 list 면 OR(`|all` 이면 AND).
- 필드 modifier: contains / startswith / endswith / re / all / cased
- 필드 경로 탐색 순서(팀 규약, 노션 6.1):
    ① top-level(src_ip/pid/ppid/timestamp…)  ② 점 경로(layer_data.event)  ③ 접두어 없는 이름 → layer_data.<이름>
  auth·audit 룰은 ②, apache 룰은 ③ 으로 쓰므로 둘 다 지원한다.
- condition: and / or / not / 괄호 / "1 of sel*" / "all of sel*" / "1 of them" / "all of them"
- 값 비교: 숫자 룰값은 숫자로 비교("33"==33), 문자열은 기본 대소문자 무시, * ? 와일드카드 지원
- logsource 라우팅: 이벤트 layer ↔ {product, service}. category 는 무시.
    system → linux/auditd, auth → linux/auth, web → apache/access, network → suricata/eve
"""
from __future__ import annotations

import fnmatch
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator

from common.seed import VALID_ENTITY_TYPES, VALID_SIGNAL_TAGS, build_seed
from common.timeparse import normalize_iso
from detect.loader import Rule, RuleError, load_rules  # noqa: F401  (re-export)

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased"}
LAYER_LOGSOURCE = {
    "system": {"product": "linux", "service": "auditd"},
    "auth": {"product": "linux", "service": "auth"},
    "web": {"product": "apache", "service": "access"},
    "network": {"product": "suricata", "service": "eve"},
}
TOKEN_RE = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[A-Za-z0-9_*]+)")


# ── 필드 접근 / 값 비교 ─────────────────────────────────────────────────────
def get_field(event: dict, dotted: str) -> Any:
    """① top-level → ② 점 경로 → ③ 접두어 없는 이름은 layer_data 에서."""
    cur: Any = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            cur = None
            break
        cur = cur[part]
    if cur is None and "." not in dotted:
        cur = (event.get("layer_data") or {}).get(dotted)
    return cur


def _compare_scalar(actual: Any, expected: Any, mods: set[str]) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(_compare_scalar(a, expected, mods) for a in actual)
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    if isinstance(expected, bool):
        return actual is expected
    if isinstance(expected, (int, float)) and not (mods & {"contains", "startswith", "endswith"}):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    left, right = str(actual), str(expected)
    if "cased" not in mods:
        left, right = left.casefold(), right.casefold()
    if "contains" in mods:
        return right in left
    if "startswith" in mods:
        return left.startswith(right)
    if "endswith" in mods:
        return left.endswith(right)
    if "*" in right or "?" in right:
        return fnmatch.fnmatchcase(left, right)
    return left == right


def match_field(event: dict, expression: str, expected: Any) -> bool:
    parts = expression.split("|")
    field, mods = parts[0], set(parts[1:])
    bad = mods - SUPPORTED_MODIFIERS
    if bad:
        raise RuleError(f"unsupported modifier {sorted(bad)} in '{expression}'")
    actual = get_field(event, field)
    if expected is None:
        return actual is None
    values = expected if isinstance(expected, list) else [expected]
    results = [_compare_scalar(actual, v, mods) for v in values]
    return all(results) if "all" in mods else any(results)


def match_selection(event: dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        # list[dict] → OR. 문자열(키워드)은 이벤트 전체 JSON 에 대한 contains.
        for item in selection:
            if isinstance(item, dict):
                if match_selection(event, item):
                    return True
            elif str(item).casefold() in json.dumps(event, ensure_ascii=False).casefold():
                return True
        return False
    raise RuleError(f"unsupported selection type: {type(selection).__name__}")


# ── condition 파서 ──────────────────────────────────────────────────────────
class Cond:
    def __init__(self, condition: str, results: dict[str, bool]):
        self.tokens = self._tokenize(condition)
        self.names = tuple(results)
        self.results = results
        self.i = 0

    @staticmethod
    def _tokenize(cond: str) -> list[str]:
        out, pos = [], 0
        while pos < len(cond):
            m = TOKEN_RE.match(cond, pos)
            if not m:
                raise RuleError(f"bad condition near {cond[pos:]!r}")
            out.append(m.group(1))
            pos = m.end()
        return out

    def compile(self):
        self.i = 0
        expression = self._or()
        if self.i != len(self.tokens):
            raise RuleError(f"unexpected token {self.tokens[self.i]!r}")
        return expression

    def parse(self) -> bool:
        return _evaluate_condition(self.compile(), self.results)

    def _peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _take(self):
        t = self.tokens[self.i]
        self.i += 1
        return t

    def _or(self):
        expression = self._and()
        while self._peek() == "or":
            self._take()
            expression = ("or", expression, self._and())
        return expression

    def _and(self):
        expression = self._not()
        while self._peek() == "and":
            self._take()
            expression = ("and", expression, self._not())
        return expression

    def _not(self):
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._primary()

    def _primary(self):
        t = self._take()
        if t == "(":
            expression = self._or()
            if self._take() != ")":
                raise RuleError("missing ')'")
            return expression
        if t in ("1 of", "all of"):
            pat = self._take()
            names = list(self.names) if pat == "them" else [n for n in self.names if fnmatch.fnmatchcase(n, pat)]
            if not names:
                raise RuleError(f"'{t} {pat}' matches no selection")
            return ("any" if t == "1 of" else "all", tuple(names))
        if t not in self.names:
            raise RuleError(f"unknown selection '{t}'")
        return ("selection", t)


def _evaluate_condition(expression, results: dict[str, bool]) -> bool:
    operation = expression[0]
    if operation == "selection":
        return results[expression[1]]
    if operation == "not":
        return not _evaluate_condition(expression[1], results)
    if operation == "and":
        return _evaluate_condition(expression[1], results) and _evaluate_condition(expression[2], results)
    if operation == "or":
        return _evaluate_condition(expression[1], results) or _evaluate_condition(expression[2], results)
    values = (results[name] for name in expression[1])
    return any(values) if operation == "any" else all(values)


# ── 라우팅 / 평가 ───────────────────────────────────────────────────────────
def routed(rule: Rule, event: dict) -> bool:
    """룰 logsource(product/service) 가 이벤트 layer 에 해당하는가. category 는 무시."""
    actual = LAYER_LOGSOURCE.get(event.get("layer"), {})
    for k in ("product", "service"):
        if k in rule.logsource and rule.logsource[k] != actual.get(k):
            return False
    return True


def evaluate(rule: Rule, event: dict) -> bool:
    if not routed(rule, event):
        return False
    return _evaluate_routed(rule, event)


def _evaluate_routed(rule: Rule, event: dict) -> bool:
    results = {name: match_selection(event, sel) for name, sel in rule.selections.items()}
    return _evaluate_condition(rule.condition_expr, results)


# ── seed ────────────────────────────────────────────────────────────────────
def _parse_ts(ts_iso: str) -> datetime:
    t = datetime.fromisoformat(normalize_iso(ts_iso))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _shift(ts_iso: str, seconds: int) -> str:
    t = _parse_ts(ts_iso).astimezone(timezone.utc) + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _pick_entity(event: dict, rule: Rule) -> tuple[str, Any]:
    """x_seed_entity 중 조인키(src_ip/pid/ppid)인 것 우선, 없으면 계층 기본값."""
    default = ["pid", "src_ip", "ppid"] if event.get("layer") == "system" else ["src_ip", "pid", "ppid"]
    for name in [n for n in rule.seed_entity if n in VALID_ENTITY_TYPES] + default:
        if event.get(name) is not None:
            return name, event[name]
    return default[0], None


def make_seed(event: dict, rule: Rule, window_sec: int = 60) -> dict:
    ld = event.get("layer_data") or {}
    etype, evalue = _pick_entity(event, rule)
    tags = [ld["key"]] if ld.get("key") in VALID_SIGNAL_TAGS else []
    seed = build_seed(
        entity_type=etype, entity_value=evalue,
        window=[_shift(event["timestamp"], -window_sec), _shift(event["timestamp"], window_sec)],
        layer=event.get("layer"),
        source=["sigma"], reason=rule.title,
        rule_severity=rule.level, layer_count=1,
        signal_tags=tags, evidence_refs=[event.get("raw_ref")],
    )
    # 계약 밖 보조 정보(조사 에이전트·사람이 읽기 위한 것)
    seed["rule_id"] = rule.id
    seed["rule_name"] = rule.name
    if rule.aggregation:
        seed["aggregation"] = dict(rule.aggregation)
    seed["detail"] = {"timestamp": event.get("timestamp"), "pid": event.get("pid"), "ppid": event.get("ppid"),
                      **{k: ld.get(k) for k in ("uid", "user", "src_user", "event", "comm", "exe", "exec_args",
                                                 "path", "cwd", "method", "status", "user_agent", "command")
                         if ld.get(k) is not None}}
    return seed


def detect(events: Iterable[dict], rules: list[Rule], window_sec: int = 60) -> Iterator[tuple[dict, Rule, dict]]:
    """이벤트 스트림 × 룰 → (event, rule, seed) 를 순서대로 산출."""
    rules = tuple(rules)
    rules_by_layer = {
        layer: tuple(rule for rule in rules if routed(rule, {"layer": layer}))
        for layer in LAYER_LOGSOURCE
    }
    for ev in events:
        candidates = rules_by_layer.get(ev.get("layer"))
        if candidates is None:
            candidates = tuple(rule for rule in rules if routed(rule, ev))
        for r in candidates:
            if _evaluate_routed(r, ev):
                yield ev, r, make_seed(ev, r, window_sec)


def run(events: Iterable[dict], rules: list[Rule], window_sec: int = 60) -> list[dict]:
    """seed 리스트만 필요할 때."""
    return [seed for _, _, seed in detect(events, rules, window_sec)]

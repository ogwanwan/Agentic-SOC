"""detect/loader.py — Sigma 룰 로더 (② 탐지의 입력 준비)

역할: detect/rules/sigma/**/*.yml 을 읽어 Rule 객체 목록으로 만든다. 이벤트는 모른다.
  - 필수 키(title/id/logsource/detection/level, detection.condition) 검증
  - condition 문법을 로드 시점에 한 번 파싱해 오타를 미리 잡는다
  - x_correlation / x_seed_entity 같은 팀 확장 키는 data 에 그대로 보존

매칭(이벤트 × 룰)은 detect/engine.py 가 담당한다.
"""
from __future__ import annotations

from pathlib import Path

import yaml


class RuleError(ValueError):
    pass


class Rule:
    REQUIRED = ("title", "id", "logsource", "detection", "level")

    def __init__(self, data: dict, path: Path):
        missing = [k for k in self.REQUIRED if k not in data]
        if missing:
            raise RuleError(f"{path.name}: missing {missing}")
        det = data["detection"]
        if not isinstance(det, dict) or "condition" not in det:
            raise RuleError(f"{path.name}: detection.condition required")
        self.data, self.path = data, Path(path)
        self.id, self.title, self.level = data["id"], data["title"], data["level"]
        self.logsource = data["logsource"] or {}
        self.selections = {k: v for k, v in det.items() if k != "condition"}
        self.condition = det["condition"]
        self.tags = data.get("tags", []) or []
        self.seed_entity = data.get("x_seed_entity") or []
        self.aggregation = data.get("x_aggregation")
        if self.aggregation is not None:
            if not isinstance(self.aggregation, dict):
                raise RuleError(f"{path.name}: x_aggregation must be a mapping")
            window = self.aggregation.get("window_seconds")
            count = self.aggregation.get("min_count")
            if isinstance(window, bool) or not isinstance(window, (int, float)) or window <= 0:
                raise RuleError(f"{path.name}: x_aggregation.window_seconds must be positive")
            if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                raise RuleError(f"{path.name}: x_aggregation.min_count must be a positive integer")
        # 로드 시 condition을 한 번 파싱·컴파일한다. 순환 import 회피용 지연 import.
        from detect.engine import Cond
        self.condition_expr = Cond(
            self.condition, {name: False for name in self.selections}
        ).compile()

    @property
    def name(self) -> str:
        return self.path.stem

    def __repr__(self) -> str:
        return f"Rule({self.name!r}, level={self.level!r})"


def load_rule(path: str | Path) -> Rule:
    p = Path(path)
    with open(p, encoding="utf-8-sig") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise RuleError(f"{p.name}: not a mapping")
    return Rule(data, p)


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """rules_dir 아래 모든 *.yml 을 재귀로 로드(파일명 순)."""
    rules = [load_rule(p) for p in sorted(Path(rules_dir).rglob("*.yml"))]
    if not rules:
        raise RuleError(f"no *.yml under {rules_dir}")
    return rules


if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from collections import Counter
    rs = load_rules(os.path.join(os.path.dirname(__file__), "rules", "sigma"))
    print("룰 %d개 로드: %s" % (len(rs), dict(Counter(r.path.parent.name for r in rs))))
    for r in rs:
        print("  %-8s %-45s [%s]" % (r.path.parent.name, r.name, r.level))

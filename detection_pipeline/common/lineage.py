"""common/lineage.py — audit(system) 계층 내부 ppid→pid 프로세스 계보 (webshell_local 조인)

조인키 정의(common/join_keys.py)의 "웹셸 로컬: ppid→pid 계보"를 실제로 조립한다.

핵심 아이디어: 노드는 pid 번호가 아니라 "그 번호를 그 시간 동안 쓴 한 프로세스"(인스턴스)다.
pid 는 번호표처럼 재사용되므로 번호만 이으면 아침의 cron 과 저녁의 웹셸이 부모-자식으로 엮인다.
인스턴스를 나누는 기준은 두 가지:
  1) 재부팅 경계 — serial 은 부팅마다 1부터 다시 오르므로, 시간순으로 훑다 serial 이
     SERIAL_RESET_SLACK 이상 줄면 부팅 세대(epoch)를 올린다. 세대가 다르면 같은 pid 도 남남.
  2) ppid 변경 — 살아 있는 프로세스는 부모를 못 바꾼다. 같은 (epoch, pid) 관측열에서 ppid 가
     바뀌면 번호가 재사용된 것. 예외: 부모가 먼저 죽어 init(1) 에 입양된 경우(ppid→1)는
     같은 인스턴스로 두고 warning 만 남긴다. comm/exe 변화는 execve 체인(sh→curl)이라 기준 아님.

부모 연결: 같은 epoch 에서 pid==ppid 인 인스턴스 중 "자식이 태어나기 전(+PARENT_SLACK)에
이미 있던 것 가운데 가장 최근 것". 후보가 없으면 오류가 아니라 parent_not_observed(끊김).
uid 는 조건으로 쓰지 않는다 — sudo(uid 33) → useradd(uid 0) 같은 권한 상승이 곧 탐지 신호다.

이 모듈은 파일을 읽거나 쓰지 않고, 입력 순서와 무관하게 같은 결과를 낸다.

1단계(이 파일): build_process_index — 인스턴스 분할 + 부모/자식 연결.
2단계: ancestors / descendants.  3단계: lineage_for_seed(join_path 조각) + join_keys 래퍼.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from common.timeparse import normalize_iso

# --- 상수 -------------------------------------------------------------------
SERIAL_RESET_SLACK = 1000      # serial 이 이만큼 이상 줄면 재부팅으로 본다(파서 200개 창 재정렬 여유)
PARENT_SLACK_SECONDS = 2.0     # 부모 first_seen 이 자식보다 이만큼 늦어도 허용(데몬은 늦게 관측될 수 있음)
REPARENT_PPID = 1              # 부모 사망 후 입양되는 init 의 pid
ROOT_PPIDS = (0, 1)            # 여기 닿으면 조상 탐색 종료(뿌리)

WARN_REPARENTED = "REPARENTED_TO_INIT"
WARN_PPID_MISSING = "PPID_MISSING_IN_SOME_RECORDS"


# --- 시간 -------------------------------------------------------------------
def parse_ts(value: Any) -> Optional[datetime]:
    """ISO8601(Z / +00:00) → aware UTC datetime. 실패하면 None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(normalize_iso(value))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# --- 인스턴스 ---------------------------------------------------------------
@dataclass
class ProcessInstance:
    """같은 (epoch, pid) 를 같은 부모 아래서 연속으로 쓴 한 프로세스."""
    key: tuple                       # (epoch, pid, seq) — seq 는 같은 (epoch,pid) 안에서 0,1,2…
    epoch: int
    pid: int
    ppid: Optional[int]              # 최초 관측된 부모(입양 전 원래 부모)
    first_seen: datetime
    last_seen: datetime
    raw_refs: list = field(default_factory=list)     # 근거 원본 줄(시간순)
    events: list = field(default_factory=list)       # 관측 이벤트(시간순)
    uids: list = field(default_factory=list)         # 관측된 uid(등장 순, 중복 제거)
    comms: list = field(default_factory=list)        # 관측된 comm(등장 순, 중복 제거)
    exes: list = field(default_factory=list)
    parent_key: Optional[tuple] = None
    warnings: list = field(default_factory=list)

    @property
    def uid_first(self) -> Optional[int]:
        return self.uids[0] if self.uids else None

    def to_dict(self) -> dict:
        return {
            "key": list(self.key),
            "epoch": self.epoch,
            "pid": self.pid,
            "ppid": self.ppid,
            "first_seen": format_ts(self.first_seen),
            "last_seen": format_ts(self.last_seen),
            "uids": list(self.uids),
            "comms": list(self.comms),
            "exes": list(self.exes),
            "raw_refs": list(self.raw_refs),
            "parent": list(self.parent_key) if self.parent_key else None,
            "warnings": list(self.warnings),
        }


def _append_unique(lst: list, value: Any) -> None:
    if value is not None and value not in lst:
        lst.append(value)


class ProcessIndex:
    """build_process_index 의 결과. 인스턴스 + 부모/자식 관계 + 이벤트→인스턴스 매핑."""

    def __init__(self) -> None:
        self.instances: dict[tuple, ProcessInstance] = {}
        self.by_epoch_pid: dict[tuple, list] = {}        # (epoch, pid) → [key…] first_seen 순
        self.children: dict[tuple, list] = {}            # parent key → [child key…] first_seen 순
        self.by_raw_ref: dict[str, tuple] = {}           # raw_ref → key
        self.by_event_id: dict[int, tuple] = {}          # id(event) → key (raw_ref 없는 이벤트용)
        self.epoch_count: int = 0
        self.skipped: int = 0                            # system 계층이 아니거나 pid/timestamp 없는 이벤트 수

    # -- 조회 ---------------------------------------------------------------
    def instance_for_event(self, event: dict) -> Optional[ProcessInstance]:
        """이벤트 → 그 이벤트가 속한 인스턴스. raw_ref 로 찾고, 없으면 객체 동일성으로 찾는다."""
        if not isinstance(event, dict):
            return None
        raw_ref = event.get("raw_ref")
        key = self.by_raw_ref.get(str(raw_ref)) if raw_ref not in (None, "") else None
        if key is None:
            key = self.by_event_id.get(id(event))
        return self.instances.get(key) if key else None

    def instances_of(self, epoch: int, pid: int) -> list:
        return [self.instances[k] for k in self.by_epoch_pid.get((epoch, pid), [])]

    def instance_at(self, epoch: int, pid: int, ts: datetime,
                    slack_seconds: float = PARENT_SLACK_SECONDS) -> Optional[ProcessInstance]:
        """ts 시점에 살아 있던 (epoch,pid) 인스턴스: first_seen <= ts + slack 인 것 중 가장 최근."""
        chosen = None
        limit = ts.timestamp() + slack_seconds
        for inst in self.instances_of(epoch, pid):
            if inst.first_seen.timestamp() <= limit:
                chosen = inst          # first_seen 오름차순이므로 마지막 통과 항목이 가장 최근
            else:
                break
        return chosen

    def parent_of(self, inst: ProcessInstance) -> Optional[ProcessInstance]:
        return self.instances.get(inst.parent_key) if inst.parent_key else None

    def children_of(self, inst: ProcessInstance) -> list:
        return [self.instances[k] for k in self.children.get(inst.key, [])]

    def to_dict(self) -> dict:
        """결정론 검증·디버깅용 직렬화."""
        return {
            "epoch_count": self.epoch_count,
            "skipped": self.skipped,
            "instances": [self.instances[k].to_dict() for k in sorted(self.instances)],
        }


# --- 빌드 -------------------------------------------------------------------
def _observation(event: Any) -> Optional[tuple]:
    """system 이벤트 → (ts, serial, raw_ref, pid, ppid, event). 조건 미달이면 None."""
    if not isinstance(event, dict) or event.get("layer") != "system":
        return None
    pid = event.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool):
        return None
    ts = parse_ts(event.get("timestamp"))
    if ts is None:
        return None
    ld = event.get("layer_data") or {}
    serial = ld.get("serial")
    if not isinstance(serial, int) or isinstance(serial, bool):
        serial = None
    ppid = event.get("ppid")
    if not isinstance(ppid, int) or isinstance(ppid, bool):
        ppid = None
    raw_ref = str(event.get("raw_ref") or "")
    return ts, serial, raw_ref, pid, ppid, event


def _assign_epochs(observations: list, serial_reset_slack: int) -> list:
    """시간순 관측열에 부팅 세대를 붙인다. serial 이 최대치보다 slack 이상 줄면 새 세대."""
    out, epoch, max_serial = [], 0, None
    for ts, serial, raw_ref, pid, ppid, ev in observations:
        if serial is not None:
            if max_serial is not None and serial < max_serial - serial_reset_slack:
                epoch += 1
                max_serial = serial
            else:
                max_serial = serial if max_serial is None else max(max_serial, serial)
        out.append((epoch, ts, serial, raw_ref, pid, ppid, ev))
    return out


def build_process_index(events: Iterable[dict],
                        serial_reset_slack: int = SERIAL_RESET_SLACK,
                        parent_slack_seconds: float = PARENT_SLACK_SECONDS) -> ProcessIndex:
    """공통스키마 system 이벤트 → ProcessIndex. 입력 순서 무관, 파일 I/O 없음."""
    if isinstance(serial_reset_slack, bool) or not isinstance(serial_reset_slack, int) or serial_reset_slack < 0:
        raise ValueError("serial_reset_slack 은 0 이상의 정수여야 함")
    if isinstance(parent_slack_seconds, bool) or not isinstance(parent_slack_seconds, (int, float)) \
            or parent_slack_seconds < 0:
        raise ValueError("parent_slack_seconds 는 0 이상의 숫자여야 함")

    index = ProcessIndex()

    # 1) 관측 추출 + 결정론 정렬(timestamp, serial, raw_ref)
    observations = []
    for ev in events:
        obs = _observation(ev)
        if obs is None:
            index.skipped += 1
            continue
        observations.append(obs)
    observations.sort(key=lambda o: (o[0], o[1] if o[1] is not None else -1, o[2]))

    # 2) 부팅 세대
    observations = _assign_epochs(observations, serial_reset_slack)
    index.epoch_count = (observations[-1][0] + 1) if observations else 0

    # 3) (epoch, pid) 별 인스턴스 분할
    grouped: dict[tuple, list] = {}
    for obs in observations:
        grouped.setdefault((obs[0], obs[4]), []).append(obs)

    for (epoch, pid) in sorted(grouped):
        seq, current = 0, None
        for _, ts, serial, raw_ref, _, ppid, ev in grouped[(epoch, pid)]:
            split = False
            if current is None:
                split = True
            elif ppid is not None and current.ppid is not None and ppid != current.ppid:
                if ppid == REPARENT_PPID:
                    _append_unique(current.warnings, WARN_REPARENTED)   # 입양: 같은 프로세스
                else:
                    split = True                                         # 번호 재사용: 새 프로세스
            if split:
                current = ProcessInstance(key=(epoch, pid, seq), epoch=epoch, pid=pid, ppid=ppid,
                                          first_seen=ts, last_seen=ts)
                index.instances[current.key] = current
                index.by_epoch_pid.setdefault((epoch, pid), []).append(current.key)
                seq += 1
            elif current.ppid is None and ppid is not None:
                current.ppid = ppid                                      # 앞선 레코드에 ppid 가 없었던 경우
            if ppid is None:
                _append_unique(current.warnings, WARN_PPID_MISSING)

            current.last_seen = ts
            current.events.append(ev)
            index.by_event_id[id(ev)] = current.key
            if raw_ref:
                current.raw_refs.append(raw_ref)
                index.by_raw_ref[raw_ref] = current.key
            ld = ev.get("layer_data") or {}
            _append_unique(current.uids, ld.get("uid"))
            _append_unique(current.comms, ld.get("comm"))
            _append_unique(current.exes, ld.get("exe"))

    # 4) 부모 연결: 같은 epoch, pid==ppid, 자식 first_seen(+slack) 이전에 존재한 가장 최근 인스턴스
    for key in sorted(index.instances):
        inst = index.instances[key]
        if inst.ppid is None or inst.ppid in ROOT_PPIDS or inst.ppid == inst.pid:
            continue
        parent = index.instance_at(inst.epoch, inst.ppid, inst.first_seen, parent_slack_seconds)
        if parent is None:
            continue
        inst.parent_key = parent.key
        index.children.setdefault(parent.key, []).append(inst.key)

    for child_keys in index.children.values():
        child_keys.sort(key=lambda k: (index.instances[k].first_seen, k))

    return index


__all__ = [
    "SERIAL_RESET_SLACK", "PARENT_SLACK_SECONDS", "REPARENT_PPID", "ROOT_PPIDS",
    "WARN_REPARENTED", "WARN_PPID_MISSING",
    "ProcessInstance", "ProcessIndex", "build_process_index", "parse_ts", "format_ts",
]

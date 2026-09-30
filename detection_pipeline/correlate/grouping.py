"""
correlate/grouping.py — 사건 묶기 총괄 (통합)

입력: normalize_all() 이벤트 스트림 + 탐지가 만든 seed(앵커)
처리: links/ 자동 로드 → 전 계층쌍 edge 수집 → guards(오연결 방지) → 클러스터 → Incident
출력: Incident 리스트 → Triage/조사 에이전트

담당자는 links/<pair>.py 에 @register_linker edge 함수만 추가하면 자동으로 합류한다
(이 파일은 안 건드림).
"""

import os
import importlib

import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate.registry import LINKERS
from correlate.guards import apply_guards
from correlate.incident import build_incident
from correlate.dedup import dedup_incidents


def _load_linkers():
    """links/ 폴더의 모든 pair 모듈을 import 해 @register_linker 를 발동시킨다."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "links")
    if not os.path.isdir(d):
        return
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".py") and not fn.startswith("_"):
            try:
                importlib.import_module("correlate.links." + fn[:-3])
            except Exception as exc:  # 한 링크가 깨져도 나머지는 돌아간다
                print("[correlate] 링크 로드 실패 %s: %s" % (fn, exc))


def _clusters(nodes, edges):
    """union-find 로 edge 로 연결된 raw_ref 들을 클러스터로 묶는다."""
    parent = {n: n for n in nodes}

    def find(x):
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    for e in edges:
        a, b = e["a"], e["b"]
        if a in parent and b in parent:
            parent[find(a)] = find(b)

    groups = {}
    for n in nodes:
        groups.setdefault(find(n), []).append(n)
    return list(groups.values())


MAX_INCIDENT_MEMBERS = 500


def correlate(events, seeds=None, require_seed=False, max_members=MAX_INCIDENT_MEMBERS, dedup=True):
    """이벤트 + seed → Incident 리스트.

    require_seed=True 면 탐지 seed 가 하나도 안 걸린 클러스터(= 계보만으로 뭉친 blob)는
    사건으로 내보내지 않는다. 탐지 근거 없는 프로세스 트리가 사건 목록을 채우는 것을 막는다.
    max_members: 이 수를 넘는 거대 사건은 멤버 목록을 잘라 실어 보낸다(트리아지 입력 폭주 방지).
    None 이면 자르지 않는다.
    dedup=True 면 같은 (entity, 사유) 로 쪼개진 파편 사건을 한 건으로 병합한다(스캐너 반복요청 폭주 방지).
    """
    seeds = list(seeds or [])
    _load_linkers()
    by_ref = {e["raw_ref"]: e for e in events}

    # 1) 전 계층쌍 edge 수집 → 2) 오연결 방지
    edges = []
    for linker in LINKERS:
        edges += linker(events)
    edges = apply_guards(edges, events)

    # 3) edge 로 연결된 노드만 클러스터 대상
    nodes = set()
    for e in edges:
        nodes.add(e["a"])
        nodes.add(e["b"])

    incidents = []
    used = set()
    clusters = _clusters(nodes, edges)
    cluster_by_ref = {
        raw_ref: cluster_index
        for cluster_index, cluster in enumerate(clusters)
        for raw_ref in cluster
    }
    edges_by_cluster = [[] for _ in clusters]
    for edge in edges:
        cluster_index = cluster_by_ref.get(edge["a"])
        if cluster_index is not None and cluster_by_ref.get(edge["b"]) == cluster_index:
            edges_by_cluster[cluster_index].append(edge)

    for cluster_index, cluster in enumerate(clusters):
        cset = set(cluster)
        cev = [by_ref[r] for r in cluster if r in by_ref]
        cedges = edges_by_cluster[cluster_index]
        cseeds = [s for s in seeds if set(s.get("evidence_refs", [])) & cset]
        for s in cseeds:
            used.add(id(s))
        if require_seed and not cseeds:
            continue  # 탐지 근거 없는 blob → 사건화 안 함
        incidents.append(build_incident(cev, cedges, cseeds, max_members=max_members))

    # 4) 어느 클러스터에도 안 붙은 seed → 단일 계층 사건(누락 방지)
    for s in seeds:
        if id(s) in used:
            continue
        cev = [by_ref[r] for r in s.get("evidence_refs", []) if r in by_ref]
        if cev:
            incidents.append(build_incident(cev, [], [s], max_members=max_members))

    # 5) 파편 병합(같은 entity+사유) — 스캐너 반복요청이 수백 사건으로 쪼개지는 것 방지
    if dedup:
        incidents = dedup_incidents(incidents, max_members=max_members)

    incidents.sort(key=lambda i: i["window"][0] or "")
    return incidents


if __name__ == "__main__":
    # 데모: normalize_all() 로 실제 이벤트를 받아 사건 묶기.
    # 운영 기본은 require_seed=True(탐지 앵커 있는 사건만) 이지만, 이 데모는 seed 없이
    # edge 만 보는 용도라 require_seed=False 로 끈다(안 그러면 항상 0건).
    from tools.normalize import normalize_all
    evs = normalize_all()
    incs = correlate(evs, require_seed=False)
    print("이벤트 %d건 → 사건 %d건" % (len(evs), len(incs)))
    for i in incs:
        print("  %s layers=%s members=%d join=%d" % (
            i["incident_id"], i["layers"], len(i["members"]), len(i["join_path"])))

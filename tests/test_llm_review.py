"""triage/llm_review.py self-check (실제 API 호출 없이 가짜 call 주입). 실행: python triage/tests/test_llm_review.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage.llm_review import llm_review, _parse


def _inc(iid, priority):
    return {"incident_id": iid, "priority": priority, "triage_score": 50,
            "entity": {"type": "src_ip", "value": "45.9.1.2"}, "layers": ["web", "system"],
            "join_path": [{"join": "web_system"}], "triage_parts": {"severity": 40},
            "seeds": [{"reason": "webshell upload"}]}


def _run():
    incs = [_inc("hi", "P1"), _inc("mid", "P2"), _inc("lo", "P3")]

    # 1) 관대한 JSON 파싱: 앞뒤 잡소리 붙어도 배열만 추출
    assert _parse('설명... [{"incident_id":"x","investigate":true,"reason":"r"}] 끝') == \
        [{"incident_id": "x", "investigate": True, "reason": "r"}]
    assert _parse("no json here") == []
    # 1-b) 버그#3: 배열 뒤에 또 다른 [..] 나 인용이 붙어도 첫 배열만 파싱(rfind 방식은 여기서 깨졌음)
    assert _parse('[{"incident_id":"a","investigate":true,"reason":"웹셸[1] 참고"}] 추가설명 [1]') == \
        [{"incident_id": "a", "investigate": True, "reason": "웹셸[1] 참고"}]

    # 2) 가짜 call 주입 → P1/P2 만 llm 필드 부착, P3 는 손 안 댐
    seen = {}
    def fake(digests):
        seen["ids"] = [d["incident_id"] for d in digests]
        seen["keys"] = set(digests[0].keys())
        return [{"incident_id": "hi", "investigate": True, "reason": "웹셸 업로드 정황"},
                {"incident_id": "mid", "investigate": False, "reason": "정상 스캐너로 보임"}]
    out = llm_review(incs, call=fake)
    assert seen["ids"] == ["hi", "mid"], f"대상은 P1/P2 뿐이어야: {seen['ids']}"
    assert "detect_reasons" in seen["keys"] and "members" not in seen["keys"], "digest는 증거 원문 제외"
    assert out[0]["llm_investigate"] is True and out[0]["llm_reason"] == "웹셸 업로드 정황"
    assert out[1]["llm_investigate"] is False
    assert "llm_reason" not in out[2], "P3 는 LLM 재검토 대상 아님"

    # 3) 호출 예외 → 조용히 결정론-only(필드 없음, 예외 전파 안 함)
    def boom(_digests):
        raise RuntimeError("429 rate limit")
    out = llm_review([_inc("a", "P1")], call=boom)
    assert "llm_reason" not in out[0], "실패 시 격하되어야"

    # 4) 대상 없으면(P3/P4만) 그대로 통과 — call 호출조차 안 함
    called = []
    llm_review([_inc("z", "P4")], call=lambda d: called.append(1) or [])
    assert not called, "재검토 대상 없으면 LLM 호출 안 함"

    # 5) reason 200자 절단
    long = llm_review([_inc("a", "P1")],
                      call=lambda d: [{"incident_id": "a", "investigate": True, "reason": "가" * 500}])
    assert len(long[0]["llm_reason"]) == 200

    # 6) 버그#2: investigate 가 문자열 "false" 로 와도 False 로 처리(예전엔 truthy 라 True)
    s = llm_review([_inc("a", "P1")],
                   call=lambda d: [{"incident_id": "a", "investigate": "false", "reason": "정상"}])
    assert s[0]["llm_investigate"] is False, "문자열 'false' 가 True 로 샜음"
    s = llm_review([_inc("b", "P1")],
                   call=lambda d: [{"incident_id": "b", "investigate": "true", "reason": "의심"}])
    assert s[0]["llm_investigate"] is True

    print("test_llm_review OK →", [(i["incident_id"], i.get("llm_investigate")) for i in out])


if __name__ == "__main__":
    _run()

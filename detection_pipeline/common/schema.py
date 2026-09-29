# common/schema.py - 공통스키마

"""
모든 fetch_*_log 도구는 이 모양의 dict를 반환한다.
구조:
  - 상단: 전 계층 공통 필드 (timestamp/layer/raw_ref) + 조인키(src_ip/pid/ppid)
  - layer_data: 계층 고유 데이터 (계층마다 키가 다름)

두 가지를 제공한다:
  1) build_event(...)      : 공통스키마 dict를 만들어주는 헬퍼
  2) validate(event)       : dict가 스키마를 지키는지 검사 (도구 출력 검증용)
"""

# --- 상수 -------------------------------------------------------------------
VALID_LAYERS = {"web", "network", "system", "auth"}

# 상단(top-level) 필수/선택 필드
REQUIRED_TOP = ("timestamp", "layer", "raw_ref")
JOIN_KEYS = ("src_ip", "pid", "ppid")   # 해당 계층에 있으면 채우고 없으면 None

# 계층별 layer_data에서 기대하는 키(검증·문서화용, 강제는 최소만)
LAYER_DATA_KEYS = {
    "web":     ["request_id", "method", "path", "status", "scheme",
                "host", "user_agent", "referer", "bytes", "duration_us"],
    # network: Suricata eve.json(http/alert) 파서에 맞춤. 실 클라이언트 IP는
    #          layer_data 가 아니라 top-level src_ip(조인키)로 승격(설계 문서).
    "network": ["event_type", "signature", "signature_id", "category", "severity", "action",
                "flow_id", "community_id", "in_iface", "tx_id",
                "method", "url", "url_path", "url_query", "status",
                "http_host", "http_user_agent", "http_version",
                "dest_ip", "dest_port", "transport_src_ip", "transport_src_port",
                "transport_dest_port", "protocol",
                "xff_raw", "xff_ips", "xff_resolution", "xff_status", "sensor_id"],
    # system: tools/fetch_audit_log.py 출력에 맞춤. IP 없음(src_ip=None), 조인키는 pid/ppid.
    #         path = PARENT 가 아닌 대표 PATH 항목, raw_lines = serial 묶음의 전체 줄번호(역추적).
    "system":  ["serial", "record_types", "syscall", "key", "exe", "comm", "user", "cwd",
                "exec_args", "argv", "proctitle", "path", "paths", "success", "exit",
                "uid", "euid", "auid", "ses", "tty", "session_type", "arch", "raw_lines"],
    # auth: 실 auth_parser 출력에 맞춤. 원격 IP는 layer_data.rhost 가 아니라
    #       top-level src_ip(조인키)로 둔다(apache 와 일관). 룰은 src_ip 를 참조.
    "auth":    ["host", "program", "event", "result",
                "user", "src_user", "uid", "src_uid", "gid",
                "tty", "session_type", "pwd", "command",
                "method", "invalid_user", "key_type", "key_fp", "rport",
                "pam_service", "reason", "group", "shell", "home",
                "changed_attr", "old_value", "new_value",
                "repeat_count", "message"],
}


# --- 1. 이벤트 생성 헬퍼 -----------------------------------------------------
def build_event(timestamp, layer, raw_ref,
                src_ip=None, pid=None, ppid=None, layer_data=None):
    """공통스키마 dict 1건을 만든다.

    조인키(src_ip/pid/ppid)는 해당 계층에 있으면 채우고 없으면 None.
    layer_data는 계층 고유 데이터 dict.
    """
    if layer not in VALID_LAYERS:
        raise ValueError("잘못된 layer: %r (허용: %s)" % (layer, VALID_LAYERS))
    return {
        "timestamp": timestamp,     # ISO8601 UTC, 전 계층 정렬축
        "layer": layer,             # web | network | system | auth
        "raw_ref": raw_ref,         # 원본 역추적 포인터 "apache_access.log:88213"
        # 조인 키 (없으면 None)
        "src_ip": src_ip,           # 웹↔네트워크
        "pid": pid,                 # 시스템↔인증
        "ppid": ppid,               # 웹셸 로컬 계보
        # 계층 고유
        "layer_data": layer_data or {},
    }


# --- 2. 검증 ----------------------------------------------------------------
def validate(event, *, strict=False):
    """event dict가 공통스키마를 지키는지 검사. 문제 있으면 ValueError.

    strict=True면 layer_data가 그 계층의 기대 키만 갖는지도 확인(선택).
    """
    if not isinstance(event, dict):
        raise ValueError("event는 dict여야 함: %r" % type(event))

    # 상단 필수 필드
    for f in REQUIRED_TOP:
        if event.get(f) in (None, ""):
            raise ValueError("필수 필드 없음/빈값: %r" % f)

    # layer 값 검사
    if event["layer"] not in VALID_LAYERS:
        raise ValueError("잘못된 layer: %r" % event["layer"])

    # 조인키 키 자체는 존재해야 함(값은 None 허용)
    for k in JOIN_KEYS:
        if k not in event:
            raise ValueError("조인키 필드 누락: %r (값은 None이라도 키는 있어야)" % k)

    # layer_data 존재
    if "layer_data" not in event or not isinstance(event["layer_data"], dict):
        raise ValueError("layer_data(dict) 필요")

    # (선택) 계층별 layer_data 키 검증
    if strict:
        expected = set(LAYER_DATA_KEYS.get(event["layer"], []))
        unknown = set(event["layer_data"]) - expected
        if unknown:
            raise ValueError(
                "layer=%s 에 알 수 없는 layer_data 키: %s" % (event["layer"], unknown)
            )

    return True


# --- 3. 편의 접근자 ----------------------------------------------------------
def get_field(event, key, default=None):
    """상단이든 layer_data든 key를 찾아 반환. 탐지 엔진이 계층 안 가리고 꺼낼 때 사용.

    예: get_field(ev, "method")  → web이면 layer_data.method
        get_field(ev, "src_ip")  → 상단 src_ip
    """
    if key in event:                    # 상단 필드 우선
        return event[key]
    return event.get("layer_data", {}).get(key, default)


if __name__ == "__main__":
    # 간단 자체 테스트
    ev = build_event(
        timestamp="2026-09-07T15:34:45.024347Z",
        layer="web",
        raw_ref="apache_access.log:88213",
        src_ip="54.180.11.0",
        layer_data={"method": "POST", "path": "/wp-login.php", "status": 200},
    )
    assert validate(ev)
    assert get_field(ev, "method") == "POST"     # layer_data에서
    assert get_field(ev, "src_ip") == "54.180.11.0"  # 상단에서
    print("schema.py OK:", ev)
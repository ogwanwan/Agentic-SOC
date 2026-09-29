import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection_pipeline"))

from detect.suricata_seed import build_suricata_seeds
from detect.web_network_correlation import build_web_network_correlation_index


def web_event(
    *,
    raw_ref="access.log:1",
    timestamp="2026-09-18T00:00:00.200000Z",
    src_ip="198.51.100.10",
    method="GET",
    path="/admin",
    status=200,
):
    return {
        "timestamp": timestamp,
        "layer": "web",
        "raw_ref": raw_ref,
        "src_ip": src_ip,
        "pid": None,
        "ppid": None,
        "layer_data": {
            "request_id": "request-1",
            "method": method,
            "path": path,
            "status": status,
            "host": "example.test",
        },
    }


def network_http(
    *,
    raw_ref="eve.json:1",
    timestamp="2026-09-18T00:00:00Z",
    src_ip="198.51.100.10",
    method="GET",
    path="/admin",
    status=200,
    xff_status="valid",
    xff_resolution="direct",
    flow_id=10,
    tx_id=7,
):
    return {
        "timestamp": timestamp,
        "layer": "network",
        "raw_ref": raw_ref,
        "src_ip": src_ip,
        "pid": None,
        "ppid": None,
        "layer_data": {
            "event_type": "http",
            "method": method,
            "url_path": path,
            "status": status,
            "http_host": "example.test",
            "flow_id": flow_id,
            "tx_id": tx_id,
            "sensor_id": "sensor-a",
            "transport_src_ip": "127.0.0.1",
            "transport_src_port": 50000,
            "dest_ip": "127.0.0.1",
            "dest_port": 80,
            "transport_dest_port": 80,
            "protocol": "TCP",
            "xff_status": xff_status,
            "xff_resolution": xff_resolution,
        },
    }


def network_alert(*, raw_ref="eve.json:2", src_ip="8.8.8.8", flow_id=10, tx_id=7):
    event = network_http(
        raw_ref=raw_ref,
        timestamp="2026-09-18T00:00:00.100000Z",
        src_ip=src_ip,
        flow_id=flow_id,
        tx_id=tx_id,
    )
    event["layer_data"].update({
        "event_type": "alert",
        "signature": "ET TEST",
        "signature_id": 1001,
        "category": "Test",
        "severity": 2,
        "action": "allowed",
    })
    return event


class WebNetworkCorrelationTests(unittest.TestCase):
    def test_unique_exact_request_within_one_second_is_strong(self):
        http = network_http()
        index = build_web_network_correlation_index([
            web_event(path="/admin?source=apache"),
            http,
        ])
        result = index[http["raw_ref"]]
        self.assertEqual("strong", result["join_status"])
        self.assertEqual("exact_unique_within_strong_window", result["join_reason"])
        self.assertEqual(200.0, result["delta_ms"])
        self.assertEqual(["access.log:1", "eve.json:1"], result["evidence_refs"])
        self.assertEqual(64, len(result["join_id"]))
        self.assertEqual(10, result["network_flow"]["flow_id"])

    def test_ipv6_addresses_are_canonicalized_before_matching(self):
        http = network_http(src_ip="2001:db8::1")
        apache = web_event(src_ip="2001:0db8:0:0:0:0:0:1")
        result = build_web_network_correlation_index([http, apache])["eve.json:1"]
        self.assertEqual("strong", result["join_status"])
        self.assertEqual("2001:db8::1", result["src_ip"])

    def test_multiple_exact_candidates_are_ambiguous(self):
        http = network_http()
        first = web_event(raw_ref="access.log:1", timestamp="2026-09-18T00:00:00.100000Z")
        second = web_event(raw_ref="access.log:2", timestamp="2026-09-18T00:00:00.300000Z")
        result = build_web_network_correlation_index([second, http, first])["eve.json:1"]
        self.assertEqual("ambiguous_cluster", result["join_status"])
        self.assertEqual(2, result["candidate_count"])
        self.assertIsNone(result["delta_ms"])

    def test_exact_candidate_in_fallback_window_is_context_only(self):
        http = network_http()
        apache = web_event(timestamp="2026-09-18T00:00:01.500000Z")
        result = build_web_network_correlation_index([http, apache])["eve.json:1"]
        self.assertEqual("context_only", result["join_status"])
        self.assertEqual("fallback_candidate", result["join_reason"])

    def test_missing_xff_can_only_produce_context(self):
        http = network_http(src_ip=None, xff_status="missing", xff_resolution="missing")
        result = build_web_network_correlation_index([web_event(), http])["eve.json:1"]
        self.assertEqual("context_only", result["join_status"])
        self.assertTrue(result["join_reason"].startswith("xff_missing_exact_unique"))

    def test_conflicting_xff_never_uses_ipless_fallback(self):
        http = network_http(src_ip=None, xff_status="conflict", xff_resolution="conflict")
        result = build_web_network_correlation_index([web_event(), http])["eve.json:1"]
        self.assertEqual("unmatched", result["join_status"])
        self.assertEqual("xff_invalid_or_conflict", result["join_reason"])
        self.assertEqual([], result["apache_candidates"])

    def test_only_strong_apache_match_is_added_to_suricata_seed_evidence(self):
        http = network_http(src_ip="8.8.8.8")
        alert = network_alert()
        strong_apache = web_event(src_ip="8.8.8.8")
        seeds, rejects = build_suricata_seeds([strong_apache, alert, http])
        self.assertEqual([], rejects)
        self.assertEqual(
            ["access.log:1", "eve.json:1", "eve.json:2"],
            seeds[0]["evidence_refs"],
        )
        correlation = seeds[0]["detail"]["web_network_correlations"][0]
        self.assertEqual("strong", correlation["join_status"])

    def test_context_candidate_is_preserved_but_not_promoted_to_seed_evidence(self):
        http = network_http(src_ip="8.8.8.8")
        alert = network_alert()
        apache = web_event(
            src_ip="8.8.8.8",
            timestamp="2026-09-18T00:00:01.500000Z",
        )
        seeds, rejects = build_suricata_seeds([apache, alert, http])
        self.assertEqual([], rejects)
        self.assertEqual(["eve.json:1", "eve.json:2"], seeds[0]["evidence_refs"])
        correlation = seeds[0]["detail"]["web_network_correlations"][0]
        self.assertEqual("context_only", correlation["join_status"])
        self.assertEqual("access.log:1", correlation["apache_candidates"][0]["raw_ref"])


if __name__ == "__main__":
    unittest.main()

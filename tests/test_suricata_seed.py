import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection_pipeline"))

from common.seed import VALID_SIGNAL_TAGS, validate as validate_seed
from detect.suricata_seed import build_suricata_seeds


LEGACY_FIELDS = {
    "incident_id", "detection_source", "trigger_time",
    "trigger_description", "confidence_initial", "severity_hint",
    "priority", "host", "src_ip", "reasoning", "detection_metadata",
}


def network_event(
    *,
    raw_ref="eve.json:10",
    timestamp="2026-09-18T00:19:42.486162Z",
    event_type="alert",
    src_ip="8.8.8.8",
    transport_src_ip="127.0.0.1",
    flow_id=100,
    signature_id=200,
    signature="ET TEST Alert",
    severity=2,
    tx_id=0,
    sensor_id="suricata_ec2",
    transport_src_port=50000,
    dest_ip="1.1.1.1",
    dest_port=443,
):
    return {
        "timestamp": timestamp,
        "layer": "network",
        "raw_ref": raw_ref,
        "src_ip": src_ip,
        "pid": None,
        "ppid": None,
        "layer_data": {
            "event_type": event_type,
            "signature": signature,
            "signature_id": signature_id,
            "category": "Test",
            "severity": severity,
            "action": "allowed",
            "flow_id": flow_id,
            "community_id": "1:test",
            "tx_id": tx_id,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "transport_src_ip": transport_src_ip,
            "transport_src_port": transport_src_port,
            "transport_dest_port": dest_port,
            "protocol": "TCP",
            "sensor_id": sensor_id,
        },
    }


class SuricataSeedTests(unittest.TestCase):
    def test_alert_becomes_valid_common_seed(self):
        seeds, rejects = build_suricata_seeds([network_event()])
        self.assertEqual(1, len(seeds))
        self.assertEqual([], rejects)
        self.assertTrue(validate_seed(seeds[0]))
        self.assertEqual(["suricata"], seeds[0]["source"])

    def test_http_event_does_not_become_seed(self):
        seeds, rejects = build_suricata_seeds([
            network_event(event_type="http", signature_id=None),
        ])
        self.assertEqual([], seeds)
        self.assertEqual([], rejects)

    def test_http_with_same_sensor_flow_and_transaction_becomes_evidence(self):
        alert = network_event(raw_ref="eve.json:10", tx_id=7)
        http = network_event(
            raw_ref="eve.json:11",
            event_type="http",
            signature_id=None,
            tx_id=7,
        )
        seeds, rejects = build_suricata_seeds([http, alert])
        self.assertEqual([], rejects)
        self.assertEqual(
            ["eve.json:10", "eve.json:11"],
            seeds[0]["evidence_refs"],
        )

    def test_http_with_different_transaction_is_not_connected(self):
        alert = network_event(raw_ref="eve.json:10", tx_id=7)
        http = network_event(
            raw_ref="eve.json:11",
            event_type="http",
            signature_id=None,
            tx_id=8,
        )
        seeds, _ = build_suricata_seeds([alert, http])
        self.assertEqual(["eve.json:10"], seeds[0]["evidence_refs"])

    def test_http_with_different_sensor_is_not_connected(self):
        alert = network_event(raw_ref="eve.json:10", tx_id=7)
        http = network_event(
            raw_ref="eve.json:11",
            event_type="http",
            signature_id=None,
            tx_id=7,
            sensor_id="another_sensor",
        )
        seeds, _ = build_suricata_seeds([alert, http])
        self.assertEqual(["eve.json:10"], seeds[0]["evidence_refs"])

    def test_missing_transaction_uses_unique_tuple_and_time_fallback(self):
        alert = network_event(raw_ref="eve.json:10", tx_id=None)
        http = network_event(
            raw_ref="eve.json:11",
            event_type="http",
            signature_id=None,
            tx_id=None,
            timestamp="2026-09-18T00:19:46.000000Z",
        )
        seeds, _ = build_suricata_seeds([alert, http])
        self.assertEqual(
            ["eve.json:10", "eve.json:11"],
            seeds[0]["evidence_refs"],
        )

    def test_missing_transaction_does_not_connect_ambiguous_http(self):
        alert = network_event(raw_ref="eve.json:10", tx_id=None)
        first_http = network_event(
            raw_ref="eve.json:11",
            event_type="http",
            signature_id=None,
            tx_id=None,
        )
        second_http = network_event(
            raw_ref="eve.json:12",
            event_type="http",
            signature_id=None,
            tx_id=None,
            timestamp="2026-09-18T00:19:43.000000Z",
        )
        seeds, _ = build_suricata_seeds([alert, first_http, second_http])
        self.assertEqual(["eve.json:10"], seeds[0]["evidence_refs"])

    def test_missing_transaction_does_not_connect_outside_time_window(self):
        alert = network_event(raw_ref="eve.json:10", tx_id=None)
        http = network_event(
            raw_ref="eve.json:11",
            event_type="http",
            signature_id=None,
            tx_id=None,
            timestamp="2026-09-18T00:19:48.000000Z",
        )
        seeds, _ = build_suricata_seeds([alert, http])
        self.assertEqual(["eve.json:10"], seeds[0]["evidence_refs"])

    def test_duplicate_flow_and_signature_merge_evidence(self):
        first = network_event(raw_ref="eve.json:10")
        second = network_event(
            raw_ref="eve.json:11",
            timestamp="2026-09-18T00:20:00+00:00",
        )
        seeds, rejects = build_suricata_seeds([second, first])
        self.assertEqual([], rejects)
        self.assertEqual(1, len(seeds))
        self.assertEqual(
            ["eve.json:10", "eve.json:11"],
            seeds[0]["evidence_refs"],
        )

    def test_same_flow_with_different_signatures_stays_separate(self):
        seeds, _ = build_suricata_seeds([
            network_event(signature_id=200),
            network_event(raw_ref="eve.json:11", signature_id=201),
        ])
        self.assertEqual(2, len(seeds))

    def test_top_level_src_ip_is_entity(self):
        seeds, _ = build_suricata_seeds([network_event(src_ip="8.8.4.4")])
        self.assertEqual("8.8.4.4", seeds[0]["entity"]["value"])

    def test_global_transport_ip_is_fallback_entity(self):
        seeds, _ = build_suricata_seeds([
            network_event(src_ip=None, transport_src_ip="9.9.9.9"),
        ])
        self.assertEqual("9.9.9.9", seeds[0]["entity"]["value"])

    def test_loopback_only_is_rejected(self):
        seeds, rejects = build_suricata_seeds([
            network_event(src_ip="127.0.0.1", transport_src_ip="127.0.0.1"),
        ])
        self.assertEqual([], seeds)
        self.assertEqual("missing_trusted_entity", rejects[0]["reason"])

    def test_plus_0000_timestamp_is_normalized_to_utc_window(self):
        seeds, _ = build_suricata_seeds([
            network_event(timestamp="2026-09-18T00:19:42.486162+0000"),
        ])
        self.assertEqual(
            "2026-09-18T00:18:42.486162Z",
            seeds[0]["window"][0],
        )

    def test_window_seconds_can_be_overridden(self):
        seeds, _ = build_suricata_seeds(
            [network_event()],
            window_seconds=300,
        )
        self.assertEqual(
            "2026-09-18T00:14:42.486162Z",
            seeds[0]["window"][0],
        )

    def test_same_events_produce_identical_output_regardless_of_order(self):
        events = [
            network_event(raw_ref="eve.json:10", severity=3),
            network_event(raw_ref="eve.json:11", severity=1),
            network_event(raw_ref="eve.json:12", flow_id=101, signature_id=201),
        ]
        first = build_suricata_seeds(events)
        shuffled = list(events)
        random.Random(42).shuffle(shuffled)
        second = build_suricata_seeds(shuffled)
        self.assertEqual(first, second)

    def test_severity_mapping(self):
        cases = [(1, "high"), (2, "medium"), (3, "low"), (None, "low")]
        for index, (severity, expected) in enumerate(cases):
            with self.subTest(severity=severity):
                event = network_event(
                    raw_ref="eve.json:%d" % (index + 1),
                    flow_id=index + 1,
                    signature_id=index + 1,
                    severity=severity,
                )
                seeds, _ = build_suricata_seeds([event])
                self.assertEqual(expected, seeds[0]["score_parts"]["rule_severity"])

    def test_missing_raw_ref_is_rejected(self):
        seeds, rejects = build_suricata_seeds([network_event(raw_ref=None)])
        self.assertEqual([], seeds)
        self.assertEqual("missing_raw_ref", rejects[0]["reason"])

    def test_seed_has_common_contract_and_team_optional_metadata(self):
        seeds, _ = build_suricata_seeds([network_event()])
        seed = seeds[0]
        self.assertTrue(LEGACY_FIELDS.isdisjoint(seed))
        self.assertLessEqual(set(seed["signal_tags"]), VALID_SIGNAL_TAGS)
        self.assertLessEqual(
            {
                "entity", "window", "layer", "source", "reason",
                "score_parts", "signal_tags", "evidence_refs",
            },
            set(seed),
        )
        self.assertEqual("200", seed["rule_id"])
        self.assertEqual("suricata_200", seed["rule_name"])
        self.assertEqual(100, seed["detail"]["flow_id"])


if __name__ == "__main__":
    unittest.main()

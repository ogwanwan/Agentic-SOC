import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection_pipeline"))

from detect.engine import Cond, detect, evaluate
from detect.loader import Rule


def rule(name, product, selection, condition="selection"):
    return Rule({
        "title": name,
        "id": name,
        "level": "high",
        "logsource": {"product": product},
        "detection": {"selection": selection, "condition": condition},
    }, Path(name + ".yml"))


class EngineOptimizationTests(unittest.TestCase):
    def test_compiled_conditions_and_layer_index_keep_results(self):
        values = {"sel_a": True, "sel_b": False, "filter_a": False}
        self.assertTrue(Cond("1 of sel_* and not 1 of filter_*", values).parse())

        rules = [
            rule("web", "apache", {"method": "GET"}),
            rule("auth", "linux", {"layer_data.event": "login"}),
        ]
        events = [
            {"timestamp": "2026-09-23T00:00:00Z", "layer": "web", "raw_ref": "web:1",
             "src_ip": "1.2.3.4", "layer_data": {"method": "GET"}},
            {"timestamp": "2026-09-23T00:00:01Z", "layer": "auth", "raw_ref": "auth:1",
             "src_ip": "1.2.3.4", "layer_data": {"event": "login"}},
        ]
        expected = [(event["raw_ref"], item.name) for event in events for item in rules if evaluate(item, event)]
        actual = [(event["raw_ref"], item.name) for event, item, _seed in detect(events, rules)]
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()

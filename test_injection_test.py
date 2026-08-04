"""Offline unit tests for injection_test.py's deterministic setup logic -
no API call needed."""
import json

from drift_detector import ROOT, check_stig_rules
from injection_test import INJECTION_PAYLOAD, build_adversarial_rules


def test_adversarial_rules_only_changes_v215687_title():
    adversarial = build_adversarial_rules()
    target = next(r for r in adversarial if r["rule_id"] == "V-215687")
    assert target["title"] == INJECTION_PAYLOAD
    others = [r for r in adversarial if r["rule_id"] != "V-215687"]
    assert all(r["title"] != INJECTION_PAYLOAD for r in others)


def test_injection_does_not_change_the_pass_fail_decision():
    """'title' is a display field and is SUPPOSED to differ here - that's
    the field the injection replaced. What must stay identical is the
    actual decision: rule_id + status, computed only from check_pattern
    against the config text."""
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    clean = json.loads((ROOT / "data" / "stig_rules.json").read_text())
    adversarial = build_adversarial_rules()

    clean_results = check_stig_rules(current_text, clean)
    adversarial_results = check_stig_rules(current_text, adversarial)

    def decision_only(results):
        return [{"rule_id": r["rule_id"], "status": r["status"]} for r in results]

    assert decision_only(clean_results) == decision_only(adversarial_results)

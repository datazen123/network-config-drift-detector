"""Offline unit tests for remediate_and_rescan.py - fully deterministic,
no API call needed."""
import json

from drift_detector import ROOT, check_inactive_interfaces, check_stig_rules, compute_compliance_score
from remediate_and_rescan import apply_remediation


def test_remediation_restores_all_three_stig_scored_failures():
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    stig_rules = json.loads((ROOT / "data" / "stig_rules.json").read_text())

    remediated_text = apply_remediation(current_text)

    stig_results = check_stig_rules(remediated_text, stig_rules)
    interface_results = check_inactive_interfaces(remediated_text)

    assert all(r["status"] == "pass" for r in stig_results)
    assert all(r["status"] == "pass" for r in interface_results)


def test_remediation_brings_the_score_to_100():
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    stig_rules = json.loads((ROOT / "data" / "stig_rules.json").read_text())
    remediated_text = apply_remediation(current_text)

    stig_results = check_stig_rules(remediated_text, stig_rules)
    interface_results = check_inactive_interfaces(remediated_text)
    score = compute_compliance_score(stig_results, interface_results)

    assert score["score"] == 100
    assert score["cat_i_open"] == 0
    assert score["cat_ii_open"] == 0
    assert score["cat_iii_open"] == 0


def test_original_before_score_is_still_65_unchanged():
    """Confirms this script doesn't quietly change the documented as-found
    finding - the original 65/100 result stays reproducible from the
    unmodified current_config.txt."""
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    stig_rules = json.loads((ROOT / "data" / "stig_rules.json").read_text())

    stig_results = check_stig_rules(current_text, stig_rules)
    interface_results = check_inactive_interfaces(current_text)
    score = compute_compliance_score(stig_results, interface_results)

    assert score["score"] == 65


def test_acl_ssh_permit_rule_is_left_untouched():
    """The ACL finding is real but deliberately out of scope for this
    script - a human decision, not auto-remediated."""
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    remediated_text = apply_remediation(current_text)
    assert "permit tcp any host 10.20.1.5 eq 22" in remediated_text


def test_remediation_only_adds_the_three_expected_lines():
    """Confirms this is a minimal, surgical fix - not a wholesale
    reversion to the baseline config (which would also silently undo the
    (temp) description change and the ACL addition, neither of which
    this script claims to fix)."""
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    remediated_text = apply_remediation(current_text)

    current_lines = set(current_text.splitlines())
    remediated_lines = remediated_text.splitlines()
    added_lines = [l for l in remediated_lines if l not in current_lines]

    assert "service password-encryption" in added_lines
    assert "login block-for 900 attempts 3 within 120" in added_lines
    assert " shutdown" in added_lines
    # exactly these 3 new lines, nothing else snuck in
    assert len(added_lines) == 3

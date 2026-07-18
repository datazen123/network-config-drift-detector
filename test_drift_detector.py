"""Offline unit tests for drift_detector.py's deterministic functions - no API key needed."""
import pytest

from drift_detector import check_inactive_interfaces, check_stig_rules, compute_diff, extract_json


def test_compute_diff_detects_added_and_removed_lines():
    baseline = "line one\nline two\nline three\n"
    current = "line one\nline three\nline four\n"
    diff = compute_diff(baseline, current)
    changes = {(d["change"], d["line"]) for d in diff}
    assert ("removed", "line two") in changes
    assert ("added", "line four") in changes


def test_compute_diff_ignores_blank_lines():
    baseline = "a\n\nb\n"
    current = "a\nb\n"
    assert compute_diff(baseline, current) == []


def test_check_stig_rules_substring_pass_and_fail():
    rules = [
        {"rule_id": "R1", "title": "T1", "requirement": "req1", "check_type": "substring", "check_pattern": "service password-encryption"},
        {"rule_id": "R2", "title": "T2", "requirement": "req2", "check_type": "substring", "check_pattern": "not present anywhere"},
    ]
    config = "hostname X\nservice password-encryption\n"
    results = {r["rule_id"]: r["status"] for r in check_stig_rules(config, rules)}
    assert results["R1"] == "pass"
    assert results["R2"] == "FAIL"


def test_check_stig_rules_substring_all_requires_every_pattern():
    rules = [{
        "rule_id": "R3", "title": "T3", "requirement": "req3",
        "check_type": "substring_all", "check_pattern": ["login on-failure log", "login on-success log"],
    }]
    only_one = "login on-failure log\n"
    both = "login on-failure log\nlogin on-success log\n"
    assert check_stig_rules(only_one, rules)[0]["status"] == "FAIL"
    assert check_stig_rules(both, rules)[0]["status"] == "pass"


def test_check_inactive_interfaces_flags_unused_interface_without_shutdown():
    config = (
        "interface GigabitEthernet0/2\n"
        " description Unused - reserved for future expansion\n"
        " no shutdown\n"
        "!\n"
    )
    results = check_inactive_interfaces(config)
    assert len(results) == 1
    assert results[0]["interface"] == "GigabitEthernet0/2"
    assert results[0]["status"] == "FAIL"


def test_check_inactive_interfaces_passes_when_shutdown_present():
    config = (
        "interface GigabitEthernet0/2\n"
        " description Unused - reserved for future expansion\n"
        " shutdown\n"
        "!\n"
    )
    results = check_inactive_interfaces(config)
    assert results[0]["status"] == "pass"


def test_check_inactive_interfaces_ignores_interfaces_that_are_in_use():
    config = (
        "interface GigabitEthernet0/1\n"
        " description Uplink to core switch\n"
        " no shutdown\n"
        "!\n"
    )
    assert check_inactive_interfaces(config) == []


def test_extract_json_strips_fences():
    assert extract_json('```json\n{"executive_summary": "ok", "findings": []}\n```') == {
        "executive_summary": "ok", "findings": [],
    }


def test_extract_json_raises_clear_error_on_malformed_json():
    with pytest.raises(RuntimeError, match="wasn't valid JSON"):
        extract_json("not json")

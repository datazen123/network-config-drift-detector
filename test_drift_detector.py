"""Offline unit tests for drift_detector.py's deterministic functions - no API key needed."""
import pytest

from drift_detector import (
    build_payload,
    check_inactive_interfaces,
    check_stig_rules,
    compute_compliance_score,
    compute_diff,
    extract_json,
    verify_findings,
)


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


RULE_FIXTURE_DEFAULTS = {"cci": "CCI-000000", "nist_800_53_control": "XX-0"}


def test_check_stig_rules_substring_pass_and_fail():
    rules = [
        {"rule_id": "R1", "title": "T1", "requirement": "req1", "severity": "CAT I", "check_type": "substring", "check_pattern": "service password-encryption", **RULE_FIXTURE_DEFAULTS},
        {"rule_id": "R2", "title": "T2", "requirement": "req2", "severity": "CAT II", "check_type": "substring", "check_pattern": "not present anywhere", **RULE_FIXTURE_DEFAULTS},
    ]
    config = "hostname X\nservice password-encryption\n"
    results = {r["rule_id"]: r["status"] for r in check_stig_rules(config, rules)}
    assert results["R1"] == "pass"
    assert results["R2"] == "FAIL"


def test_check_stig_rules_carries_through_severity():
    rules = [{"rule_id": "R1", "title": "T1", "requirement": "req1", "severity": "CAT I",
              "check_type": "substring", "check_pattern": "x", **RULE_FIXTURE_DEFAULTS}]
    assert check_stig_rules("x", rules)[0]["severity"] == "CAT I"


def test_check_stig_rules_carries_through_nist_800_53_control():
    rules = [{"rule_id": "R1", "title": "T1", "requirement": "req1", "severity": "CAT I",
              "check_type": "substring", "check_pattern": "x", "cci": "CCI-000196", "nist_800_53_control": "IA-5"}]
    result = check_stig_rules("x", rules)[0]
    assert result["cci"] == "CCI-000196"
    assert result["nist_800_53_control"] == "IA-5"


def test_check_stig_rules_substring_all_requires_every_pattern():
    rules = [{
        "rule_id": "R3", "title": "T3", "requirement": "req3", "severity": "CAT II",
        "check_type": "substring_all", "check_pattern": ["login on-failure log", "login on-success log"],
        **RULE_FIXTURE_DEFAULTS,
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


def test_extract_json_handles_top_level_array_for_correction_pass():
    assert extract_json('```json\n[{"item": "x"}]\n```') == [{"item": "x"}]


# --- build_payload / verify_findings: the deterministic citation verifier ---

def test_build_payload_assigns_namespaced_stable_ids():
    diff = [{"change": "added", "line": "no ip http server"}]
    stig_results = [{"rule_id": "V-215687", "title": "T", "requirement": "req", "status": "FAIL"}]
    interface_results = [{"interface": "Gi0/2", "should_be_shutdown": True, "is_shutdown": False, "status": "FAIL"}]

    payload, id_index = build_payload(diff, stig_results, interface_results)

    assert payload["config_diff"][0]["id"] == "diff:0"
    assert payload["stig_rule_results"][0]["id"] == "stig:V-215687"
    assert payload["interface_results"][0]["id"] == "interface:Gi0/2"
    assert set(id_index) == {"diff:0", "stig:V-215687", "interface:Gi0/2"}


def test_verify_findings_passes_a_correctly_cited_finding():
    id_index = {"stig:V-1": {"id": "stig:V-1", "status": "FAIL"}}
    findings = [{"item": "x", "source_id": "stig:V-1", "severity": "high",
                 "poam_milestone": "Fix it.", "poam_priority": "90-day"}]

    result = verify_findings(findings, id_index)

    assert result[0]["verified"] is True
    assert result[0]["verification_note"] is None


def test_verify_findings_flags_missing_source_id():
    result = verify_findings([{"item": "x", "severity": "high"}], {})
    assert result[0]["verified"] is False
    assert "no source_id" in result[0]["verification_note"]


def test_verify_findings_flags_source_id_not_in_payload():
    result = verify_findings([{"item": "x", "source_id": "stig:V-999", "severity": "high"}], {})
    assert result[0]["verified"] is False
    assert "does not match" in result[0]["verification_note"]


def test_verify_findings_flags_high_severity_on_a_passing_check_as_contradiction():
    id_index = {"stig:V-1": {"id": "stig:V-1", "status": "pass"}}
    result = verify_findings([{"item": "x", "source_id": "stig:V-1", "severity": "critical"}], id_index)
    assert result[0]["verified"] is False
    assert "contradicts" in result[0]["verification_note"]


def test_verify_findings_allows_low_severity_note_on_a_passing_check():
    id_index = {"stig:V-1": {"id": "stig:V-1", "status": "pass"}}
    result = verify_findings([{"item": "x", "source_id": "stig:V-1", "severity": "low"}], id_index)
    assert result[0]["verified"] is True


# --- compute_compliance_score: the DISA-severity-weighted scorecard ---

def test_compute_compliance_score_perfect_score_when_everything_passes():
    stig_results = [{"rule_id": "R1", "severity": "CAT I", "status": "pass"}]
    assert compute_compliance_score(stig_results, [])["score"] == 100


def test_compute_compliance_score_deducts_more_for_cat_i_than_cat_ii():
    cat_i_fail = [{"rule_id": "R1", "severity": "CAT I", "status": "FAIL"}]
    cat_ii_fail = [{"rule_id": "R2", "severity": "CAT II", "status": "FAIL"}]
    score_cat_i = compute_compliance_score(cat_i_fail, [])["score"]
    score_cat_ii = compute_compliance_score(cat_ii_fail, [])["score"]
    assert score_cat_i < score_cat_ii


def test_compute_compliance_score_never_goes_below_zero():
    many_fails = [{"rule_id": f"R{i}", "severity": "CAT I", "status": "FAIL"} for i in range(10)]
    assert compute_compliance_score(many_fails, [])["score"] == 0


def test_compute_compliance_score_counts_open_findings_by_category():
    stig_results = [
        {"rule_id": "R1", "severity": "CAT I", "status": "FAIL"},
        {"rule_id": "R2", "severity": "CAT II", "status": "FAIL"},
        {"rule_id": "R3", "severity": "CAT II", "status": "pass"},
    ]
    result = compute_compliance_score(stig_results, [])
    assert result["cat_i_open"] == 1
    assert result["cat_ii_open"] == 1


def test_compute_compliance_score_treats_failed_interfaces_as_cat_iii():
    interface_results = [{"interface": "Gi0/2", "status": "FAIL"}]
    result = compute_compliance_score([], interface_results)
    assert result["cat_iii_open"] == 1
    assert result["score"] == 95


# --- verify_findings: POA&M consistency checks on failed findings ---

def test_verify_findings_requires_poam_milestone_on_failed_check():
    id_index = {"stig:V-1": {"id": "stig:V-1", "status": "FAIL", "severity": "CAT I"}}
    finding = {"item": "x", "source_id": "stig:V-1", "severity": "high", "poam_milestone": "", "poam_priority": "immediate"}
    result = verify_findings([finding], id_index)
    assert result[0]["verified"] is False
    assert "no poam_milestone" in result[0]["verification_note"]


def test_verify_findings_requires_correct_poam_priority_for_cat_i():
    id_index = {"stig:V-1": {"id": "stig:V-1", "status": "FAIL", "severity": "CAT I"}}
    finding = {"item": "x", "source_id": "stig:V-1", "severity": "high",
               "poam_milestone": "Enable service password-encryption.", "poam_priority": "30-day"}
    result = verify_findings([finding], id_index)
    assert result[0]["verified"] is False
    assert "requires poam_priority 'immediate'" in result[0]["verification_note"]


def test_verify_findings_accepts_correct_poam_priority_for_cat_ii():
    id_index = {"stig:V-1": {"id": "stig:V-1", "status": "FAIL", "severity": "CAT II"}}
    finding = {"item": "x", "source_id": "stig:V-1", "severity": "medium",
               "poam_milestone": "Configure banner login.", "poam_priority": "30-day"}
    result = verify_findings([finding], id_index)
    assert result[0]["verified"] is True


def test_verify_findings_defaults_ungraded_interface_failures_to_90_day():
    id_index = {"interface:Gi0/2": {"id": "interface:Gi0/2", "status": "FAIL"}}
    finding = {"item": "x", "source_id": "interface:Gi0/2", "severity": "low",
               "poam_milestone": "Shut down the unused interface.", "poam_priority": "90-day"}
    result = verify_findings([finding], id_index)
    assert result[0]["verified"] is True

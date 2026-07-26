"""Property-based tests (Hypothesis) for drift_detector.py's deterministic
functions - these check invariants across hundreds of generated inputs,
not just the hand-picked examples in test_drift_detector.py. No API key or
network needed."""
from hypothesis import given, settings
from hypothesis import strategies as st

from drift_detector import check_stig_rules, compute_compliance_score

SEVERITIES = st.sampled_from(["CAT I", "CAT II", "CAT III"])


def _stig_result(severity, status):
    return {"rule_id": "V-TEST", "severity": severity, "status": status}


def _interface_result(status):
    return {"interface": "Gi0/0", "status": status}


@given(
    stig_severities=st.lists(SEVERITIES, max_size=15),
    interface_fail_count=st.integers(min_value=0, max_value=15),
)
@settings(max_examples=200)
def test_compliance_score_always_in_valid_range(stig_severities, interface_fail_count):
    """No matter how many failures of any severity mix, score is always a
    valid percentage - never negative, never over 100."""
    stig_results = [_stig_result(sev, "FAIL") for sev in stig_severities]
    interface_results = [_interface_result("FAIL") for _ in range(interface_fail_count)]

    result = compute_compliance_score(stig_results, interface_results)

    assert 0 <= result["score"] <= 100


@given(stig_severities=st.lists(SEVERITIES, min_size=1, max_size=10))
@settings(max_examples=200)
def test_compliance_score_never_increases_when_a_pass_becomes_a_fail(stig_severities):
    """Monotonicity: flipping any single passing check to FAIL can only
    hold the score steady or lower it, never raise it."""
    all_pass = [_stig_result(sev, "pass") for sev in stig_severities]
    one_failed = [_stig_result(sev, "pass") for sev in stig_severities]
    one_failed[0] = _stig_result(stig_severities[0], "FAIL")

    score_before = compute_compliance_score(all_pass, [])["score"]
    score_after = compute_compliance_score(one_failed, [])["score"]

    assert score_after <= score_before


@given(stig_severities=st.lists(SEVERITIES, max_size=10), interface_fail_count=st.integers(0, 10))
@settings(max_examples=200)
def test_compliance_score_open_counts_sum_to_total_deductions(stig_severities, interface_fail_count):
    """The three open-finding counters should always sum to the total
    number of failed checks fed in."""
    stig_results = [_stig_result(sev, "FAIL") for sev in stig_severities]
    interface_results = [_interface_result("FAIL") for _ in range(interface_fail_count)]

    result = compute_compliance_score(stig_results, interface_results)

    total_open = result["cat_i_open"] + result["cat_ii_open"] + result["cat_iii_open"]
    assert total_open == len(stig_severities) + interface_fail_count


@given(pattern=st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs")), min_size=1, max_size=20))
@settings(max_examples=200)
def test_check_stig_rules_substring_check_matches_python_in_operator(pattern):
    """check_stig_rules' 'substring' check_type should agree with plain
    Python 'in' semantics for any generated pattern/config pair - it must
    not silently diverge from the obvious interpretation."""
    rules = [{"rule_id": "R1", "title": "T", "requirement": "req", "severity": "CAT II",
              "cci": "CCI-0", "nist_800_53_control": "XX-0",
              "check_type": "substring", "check_pattern": pattern}]
    config_with_pattern = f"prefix {pattern} suffix"
    config_without = "totally unrelated content with no match here"

    result_with = check_stig_rules(config_with_pattern, rules)[0]["status"]
    assert result_with == "pass"

    if pattern not in config_without:
        result_without = check_stig_rules(config_without, rules)[0]["status"]
        assert result_without == "FAIL"

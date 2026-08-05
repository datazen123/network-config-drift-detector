"""
Remediation verification: does actually applying the recommended fixes
restore compliance?

The "Live result" section in the README documents this repo's real,
as-found finding: the demo config scores 65/100, with two real STIG
failures (CAT I password-encryption removed, CAT II login-lockout
removed) and one interface-hygiene failure. That finding stays on the
record as-is - this script does not change it or re-run it differently.

This script asks a distinct, follow-on question: if the exact fixes
`drift_detector.py`'s own Claude-drafted findings already recommend are
actually applied, does the compliance score genuinely improve when
re-scanned with the same deterministic checks? Not "would it," measured.

Applies exactly 3 commands - the real fix text for the two failed STIG
rules (`service password-encryption`, `login block-for 900 attempts 3
within 120`) plus the interface shutdown fix - to a COPY of
`data/current_config.txt`, writes the result to
`data/remediated_config.txt`, and re-runs `check_stig_rules()`,
`check_inactive_interfaces()`, and `compute_compliance_score()` - the
exact same deterministic functions `drift_detector.py` uses, not a
separate scoring path built just for this script.

**Deliberately out of scope**: the new ACL rule permitting SSH from any
source (`permit tcp any host 10.20.1.5 eq 22`). That's a real, separate
finding this repo's own Live result already flags as CRITICAL, but it
isn't part of the STIG-scored compliance calculation
(`compute_compliance_score()` only reads `stig_results` and
`interface_results`), and removing a firewall rule a vendor may still
need for active troubleshooting is a human decision, not something to
auto-apply without review. This script reports honestly that it left
that rule untouched.

Run:
    python remediate_and_rescan.py
"""
from __future__ import annotations

import json

from drift_detector import ROOT, check_inactive_interfaces, check_stig_rules, compute_compliance_score

# The exact commands V-215687 and V-215668's own fix_summary text in
# data/stig_rules.json already recommends - not new fixes invented for
# this script.
PASSWORD_ENCRYPTION_FIX = "service password-encryption"
LOGIN_LOCKOUT_FIX = "login block-for 900 attempts 3 within 120"

INTERFACE_BEFORE = (
    "interface GigabitEthernet0/2\n"
    " description Unused - reserved for future expansion\n"
    " no shutdown\n"
)
INTERFACE_AFTER = (
    "interface GigabitEthernet0/2\n"
    " description Unused - reserved for future expansion\n"
    " shutdown\n"
)


def apply_remediation(current_text: str) -> str:
    """Applies exactly the 3 fixes the repo's own findings already
    recommend for the 3 STIG-scored failures. Does not touch the ACL
    finding, which is real but out of the compliance-score's scope (see
    module docstring)."""
    if PASSWORD_ENCRYPTION_FIX in current_text:
        raise RuntimeError("Unexpected: password-encryption fix already present in current_config.txt")
    if LOGIN_LOCKOUT_FIX in current_text:
        raise RuntimeError("Unexpected: login-lockout fix already present in current_config.txt")
    if INTERFACE_BEFORE not in current_text:
        raise RuntimeError("Unexpected: interface GigabitEthernet0/2 block not found in the expected shape")

    text = current_text.replace(
        "login on-failure log",
        f"{PASSWORD_ENCRYPTION_FIX}\n!\n{LOGIN_LOCKOUT_FIX}\nlogin on-failure log",
        1,
    )
    text = text.replace(INTERFACE_BEFORE, INTERFACE_AFTER, 1)
    return text


def main() -> None:
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    stig_rules = json.loads((ROOT / "data" / "stig_rules.json").read_text())

    before_stig = check_stig_rules(current_text, stig_rules)
    before_interfaces = check_inactive_interfaces(current_text)
    before_score = compute_compliance_score(before_stig, before_interfaces)

    remediated_text = apply_remediation(current_text)
    (ROOT / "data" / "remediated_config.txt").write_text(remediated_text)

    after_stig = check_stig_rules(remediated_text, stig_rules)
    after_interfaces = check_inactive_interfaces(remediated_text)
    after_score = compute_compliance_score(after_stig, after_interfaces)

    acl_rule_still_present = "permit tcp any host 10.20.1.5 eq 22" in remediated_text

    print("=== Before remediation (as-found, matches README's documented Live result) ===")
    print(f"Compliance scorecard: {before_score['score']}/100 "
          f"(CAT I open: {before_score['cat_i_open']}, CAT II open: {before_score['cat_ii_open']}, "
          f"CAT III/ungraded open: {before_score['cat_iii_open']})")
    for r in before_stig:
        if r["status"] == "FAIL":
            print(f"  FAIL: {r['rule_id']} ({r['severity']}) - {r['title']}")
    for r in before_interfaces:
        if r["status"] == "FAIL":
            print(f"  FAIL: interface {r['interface']} not administratively shut down")

    print("\n=== After remediation (data/remediated_config.txt, re-scanned with the same checks) ===")
    print(f"Compliance scorecard: {after_score['score']}/100 "
          f"(CAT I open: {after_score['cat_i_open']}, CAT II open: {after_score['cat_ii_open']}, "
          f"CAT III/ungraded open: {after_score['cat_iii_open']})")
    remaining_fails = [r for r in after_stig if r["status"] == "FAIL"] + \
                       [r for r in after_interfaces if r["status"] == "FAIL"]
    if remaining_fails:
        for r in remaining_fails:
            print(f"  Still FAIL: {r}")
    else:
        print("  All STIG-scored and interface checks now pass.")

    print(f"\nACL SSH-permit rule left untouched (out of compliance-score scope, human decision "
          f"to remove): still present = {acl_rule_still_present}")
    print(f"\nScore improvement: {before_score['score']} -> {after_score['score']} "
          f"({after_score['score'] - before_score['score']:+d} points)")

    result = {
        "before": {"score": before_score, "stig_failures": [r for r in before_stig if r["status"] == "FAIL"],
                    "interface_failures": [r for r in before_interfaces if r["status"] == "FAIL"]},
        "after": {"score": after_score, "stig_failures": [r for r in after_stig if r["status"] == "FAIL"],
                   "interface_failures": [r for r in after_interfaces if r["status"] == "FAIL"]},
        "acl_rule_left_untouched": acl_rule_still_present,
    }
    (ROOT / "remediation_result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("\nWrote data/remediated_config.txt and remediation_result.json")


if __name__ == "__main__":
    main()

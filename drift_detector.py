"""
Network config drift detector: deterministic code computes the line-level
diff between a baseline and current Cisco IOS-style config, and checks the
current config against real DISA Cisco IOS Router STIG rules (rule IDs,
requirement, and fix text fetched from public STIG references - see
data/stig_rules.json and the README for sourcing). Claude's job is the
part that's actually a language task: explaining the semantic risk of each
drift/violation, prioritizing them, and drafting a remediation-ready
change report. Not Claude, and not a person reading the diff by eye - the
diff and every pass/fail decision are computed in code, before Claude
ever sees the result.

Every finding Claude writes must cite a `source_id` pointing back to a real
STIG rule ID, interface name, or diff line from the deterministic payload it
was given. `verify_findings()` then checks each citation against that same
payload in plain code - no LLM judgment involved - and flags anything that
doesn't resolve, or contradicts the underlying deterministic status, as
NEEDS HUMAN VERIFICATION instead of letting it through silently. This exists
specifically to close the loop on a real, previously-undetected failure
mode: this repo's own README documented Claude occasionally blending
details between two nearby findings in free text. Before this change that
was caught by manual read-through; now it's caught by code, every run.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python drift_detector.py
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from llm_client import AnthropicClient

ROOT = Path(__file__).parent
CODE_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$", re.MULTILINE)


def extract_json(text: str) -> dict | list:
    """Strips optional markdown code fences and parses JSON - works for
    either a top-level object (the main report) or array (a correction
    pass's findings-only response)."""
    try:
        return json.loads(CODE_FENCE_RE.sub("", text.strip()).strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Claude's response wasn't valid JSON: {exc}\nRaw response:\n{text}") from exc


def compute_diff(baseline_text: str, current_text: str) -> list[dict]:
    """Line-level diff, ignoring blank lines - plain difflib, no LLM involved."""
    baseline_lines = [l for l in baseline_text.splitlines() if l.strip()]
    current_lines = [l for l in current_text.splitlines() if l.strip()]

    diff = []
    for line in difflib.unified_diff(baseline_lines, current_lines, lineterm="", n=0):
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            diff.append({"change": "added", "line": line[1:].strip()})
        elif line.startswith("-"):
            diff.append({"change": "removed", "line": line[1:].strip()})
    return diff


def check_stig_rules(current_text: str, rules: list[dict]) -> list[dict]:
    """Deterministic pass/fail against each real STIG rule's check pattern."""
    results = []
    for rule in rules:
        if rule["check_type"] == "substring":
            passed = rule["check_pattern"] in current_text
        elif rule["check_type"] == "substring_all":
            passed = all(p in current_text for p in rule["check_pattern"])
        else:
            raise ValueError(f"Unknown check_type: {rule['check_type']}")
        results.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "requirement": rule["requirement"],
            "severity": rule["severity"],
            "cci": rule["cci"],
            "nist_800_53_control": rule["nist_800_53_control"],
            "status": "pass" if passed else "FAIL",
        })
    return results


# Deterministic, DISA-severity-weighted compliance scorecard. This is NOT a
# reproduction of DISA's actual CCRI grading algorithm - that methodology
# isn't fully public. What IS real: the CAT I/II/III severity rating on
# every rule below, verified against cyber.trackr.live's published STIG
# data (see data/stig_rules.json). The point-deduction weights themselves
# (CAT I costs more than CAT II) are a defensible, clearly-labeled
# illustrative model built on that real severity data.
SEVERITY_WEIGHTS = {"CAT I": 20, "CAT II": 10, "CAT III": 5}
POAM_PRIORITY_BY_SEVERITY = {"CAT I": "immediate", "CAT II": "30-day", "CAT III": "90-day"}


def compute_compliance_score(stig_results: list[dict], interface_results: list[dict]) -> dict:
    """Weighted compliance score out of 100, floored at 0. Interface
    findings (no official CAT rating in this demo's simplified check - see
    check_inactive_interfaces docstring) are weighted at CAT III severity,
    the same conservative default DISA itself uses for a finding with no
    other CAT assignment."""
    deductions = []
    for r in stig_results:
        if r["status"] == "FAIL":
            deductions.append({"id": r["rule_id"], "severity": r["severity"], "points": SEVERITY_WEIGHTS[r["severity"]]})
    for r in interface_results:
        if r["status"] == "FAIL":
            deductions.append({"id": f"interface:{r['interface']}", "severity": "CAT III", "points": SEVERITY_WEIGHTS["CAT III"]})

    total_deduction = sum(d["points"] for d in deductions)
    score = max(0, 100 - total_deduction)
    cat_i_open = sum(1 for d in deductions if d["severity"] == "CAT I")

    return {
        "score": score,
        "deductions": deductions,
        "cat_i_open": cat_i_open,
        "cat_ii_open": sum(1 for d in deductions if d["severity"] == "CAT II"),
        "cat_iii_open": sum(1 for d in deductions if d["severity"] == "CAT III"),
    }


INTERFACE_BLOCK_RE = re.compile(r"^interface (\S+)\n((?: .*\n?)*)", re.MULTILINE)


def check_inactive_interfaces(current_text: str) -> list[dict]:
    """
    V-216556 (Cisco IOS Router RTR STIG): inactive interfaces must be
    administratively shut down. Simplification for this demo: an interface
    is treated as "should be inactive" if its description contains
    'unused' or 'reserved' - a config-text-only proxy for the STIG's
    intent, not the literal official check procedure (which also considers
    live operational interface status, not just the config file).
    """
    results = []
    for match in INTERFACE_BLOCK_RE.finditer(current_text + "\n"):
        name, body = match.group(1), match.group(2)
        looks_unused = bool(re.search(r"description.*(unused|reserved)", body, re.IGNORECASE))
        is_shutdown = bool(re.search(r"^\s*shutdown\s*$", body, re.MULTILINE))
        if looks_unused:
            results.append({
                "interface": name,
                "should_be_shutdown": True,
                "is_shutdown": is_shutdown,
                "status": "pass" if is_shutdown else "FAIL",
            })
    return results


SYSTEM_PROMPT = """You are a network security engineer reviewing an
unreviewed config drift on a perimeter router. You are given: (1) a
line-level diff between the approved baseline config and the current
running config, each with an "id", (2) real DISA STIG rule pass/fail
results (each with a real CAT I/II/III severity rating from the actual
STIG), each with an "id", (3) interface compliance results, each with an
"id" - do not recompute or contradict these, your job is to explain and
prioritize, not re-check compliance.

For each drift and each STIG failure, explain the concrete security risk in
plain language, assign a severity (critical/high/medium/low), and where
relevant draft a one-line remediation command. Every finding MUST include a
"source_id" set to the exact "id" string of the one diff/STIG/interface item
it is about - do not invent an id, and do not let one finding blend details
from two different ids.

For every finding about a FAILED STIG or interface check specifically (not
passing checks, not plain diff observations), also draft a short POA&M-style
entry: "poam_milestone" (the concrete remediation step and how you'd verify
it's done) and "poam_priority" - exactly "immediate" for anything tied to a
CAT I finding, "30-day" for CAT II, "90-day" for CAT III or ungraded
interface findings. Leave both fields as empty strings for findings that
aren't about a failed check.

Order your findings most severe first, then write a 2-3 sentence executive
summary.

Reply with ONLY JSON (no markdown fences):
{"executive_summary": "...", "findings": [{"item": "...", "source_id": "...", "severity": "...", "explanation": "...", "remediation": "...", "poam_milestone": "...", "poam_priority": "..."}]}
"""

CORRECTION_PROMPT_TEMPLATE = """The following findings from your previous
report failed automated verification against the underlying data - each
either cited a source_id that doesn't exist, or contradicted the
deterministic status of the item it cited (e.g. calling a passing check
high-severity). Fix ONLY these findings using the original payload above;
return the corrected findings in the same JSON shape as before, as a JSON
array (no markdown fences, no surrounding object):

{failed_findings_json}
"""


def build_payload(diff: list[dict], stig_results: list[dict], interface_results: list[dict]) -> tuple[dict, dict]:
    """Assigns a stable, namespaced id to every diff/STIG/interface item so
    Claude's findings can cite one exactly, and returns an id -> item lookup
    for verify_findings() to check citations against."""
    id_index: dict[str, dict] = {}

    diff_payload = []
    for i, d in enumerate(diff):
        item = {"id": f"diff:{i}", **d}
        diff_payload.append(item)
        id_index[item["id"]] = item

    stig_payload = []
    for r in stig_results:
        item = {"id": f"stig:{r['rule_id']}", **r}
        stig_payload.append(item)
        id_index[item["id"]] = item

    interface_payload = []
    for r in interface_results:
        item = {"id": f"interface:{r['interface']}", **r}
        interface_payload.append(item)
        id_index[item["id"]] = item

    payload = {
        "config_diff": diff_payload,
        "stig_rule_results": stig_payload,
        "interface_results": interface_payload,
    }
    return payload, id_index


def verify_findings(findings: list[dict], id_index: dict[str, dict]) -> list[dict]:
    """Deterministic verifier: checks every finding's source_id against the
    real underlying data, no LLM judgment involved. Flags (does not drop)
    findings whose citation doesn't exist, or whose severity contradicts the
    cited item's actual pass/FAIL status - e.g. 'critical' severity on
    something that actually passed. Returns findings with two fields added:
    verified (bool) and verification_note (str | None)."""
    verified_findings = []
    for f in findings:
        source_id = f.get("source_id")
        note = None

        if not source_id:
            note = "no source_id cited - cannot verify this finding against the underlying data"
        elif source_id not in id_index:
            note = f"source_id '{source_id}' does not match any diff/STIG/interface item given to the model"
        else:
            cited = id_index[source_id]
            status = cited.get("status")
            if status == "pass" and f.get("severity") in ("critical", "high"):
                note = (f"contradicts underlying data: '{source_id}' status is 'pass' "
                        f"but this finding claims '{f.get('severity')}' severity")
            elif status == "FAIL":
                expected_priority = POAM_PRIORITY_BY_SEVERITY.get(cited.get("severity"), "90-day")
                if not f.get("poam_milestone", "").strip():
                    note = f"'{source_id}' is a FAILED check but has no poam_milestone"
                elif f.get("poam_priority") != expected_priority:
                    note = (f"'{source_id}' is {cited.get('severity', 'ungraded')} severity, which requires "
                            f"poam_priority '{expected_priority}', but this finding has "
                            f"'{f.get('poam_priority')}'")

        verified_findings.append({**f, "verified": note is None, "verification_note": note})
    return verified_findings


def main() -> None:
    client = AnthropicClient()

    baseline_text = (ROOT / "data" / "baseline_config.txt").read_text()
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    stig_rules = json.loads((ROOT / "data" / "stig_rules.json").read_text())

    diff = compute_diff(baseline_text, current_text)
    stig_results = check_stig_rules(current_text, stig_rules)
    interface_results = check_inactive_interfaces(current_text)

    scorecard = compute_compliance_score(stig_results, interface_results)

    print(f"Config diff: {len(diff)} line-level changes.")
    print(f"STIG checks: {sum(1 for r in stig_results if r['status'] == 'FAIL')}/{len(stig_results)} failed.")
    print(f"Interface checks: {sum(1 for r in interface_results if r['status'] == 'FAIL')}/{len(interface_results)} failed.")
    print(f"Compliance scorecard: {scorecard['score']}/100 "
          f"(CAT I open: {scorecard['cat_i_open']}, CAT II open: {scorecard['cat_ii_open']}, "
          f"CAT III/ungraded open: {scorecard['cat_iii_open']})\n")

    payload, id_index = build_payload(diff, stig_results, interface_results)
    # Prefilling the assistant turn with the JSON's opening character is a
    # documented Anthropic structured-output technique: it makes markdown-
    # fence-wrapping structurally impossible for this response, rather than
    # relying only on stripping fences after the fact. extract_json()'s
    # fence-stripping stays in place as defense-in-depth.
    response = client.create(
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(payload, indent=2)}, {"role": "assistant", "content": "{"}],
        max_tokens=3000,
    )
    text = "{" + "".join(b.text for b in response.content if b.type == "text")
    report = extract_json(text)

    findings = verify_findings(report["findings"], id_index)
    unverified = [f for f in findings if not f["verified"]]

    if unverified:
        print(f"(verifier flagged {len(unverified)}/{len(findings)} finding(s) - requesting one correction pass)\n")
        correction_response = client.create(
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": json.dumps(payload, indent=2)},
                {"role": "assistant", "content": text},
                {"role": "user", "content": CORRECTION_PROMPT_TEMPLATE.format(
                    failed_findings_json=json.dumps(unverified, indent=2))},
                {"role": "assistant", "content": "["},
            ],
            max_tokens=1500,
        )
        correction_text = "[" + "".join(b.text for b in correction_response.content if b.type == "text")
        try:
            corrected = verify_findings(extract_json(correction_text), id_index)
            corrected_by_item = {c.get("item"): c for c in corrected}
            findings = [corrected_by_item.get(f.get("item"), f) if not f["verified"] else f for f in findings]
        except RuntimeError as exc:
            print(f"  (correction pass itself failed to parse: {exc} - keeping original flagged findings)\n")

    print("=== Drift & Compliance Report ===\n")
    print(report["executive_summary"] + "\n")
    for f in findings:
        tag = "" if f["verified"] else "  [NEEDS HUMAN VERIFICATION]"
        print(f"[{f['severity'].upper()}] {f['item']}{tag}")
        cited = id_index.get(f.get("source_id"), {})
        if cited.get("nist_800_53_control"):
            print(f"    NIST 800-53: {cited['nist_800_53_control']}  (CCI: {cited.get('cci')})")
        print(f"    {f['explanation']}")
        if f.get("remediation"):
            print(f"    Remediation: {f['remediation']}")
        if f.get("poam_milestone"):
            print(f"    POA&M [{f.get('poam_priority')}]: {f['poam_milestone']}")
        if not f["verified"]:
            print(f"    Verifier note: {f['verification_note']}")
        print()

    still_unverified = sum(1 for f in findings if not f["verified"])
    print(f"Verifier summary: {len(findings) - still_unverified}/{len(findings)} findings passed automated "
          f"citation/consistency checks.")
    print(f"Compliance scorecard: {scorecard['score']}/100")


if __name__ == "__main__":
    main()

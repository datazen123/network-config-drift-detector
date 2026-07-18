"""
Network config drift detector: deterministic code computes the line-level
diff between a baseline and current Cisco IOS-style config, and checks the
current config against real DISA Cisco IOS Router STIG rules (rule IDs,
requirement, and fix text fetched from public STIG references - see
data/stig_rules.json and the README for sourcing). Claude's job is the
part that's actually a language task: explaining the semantic risk of each
drift/violation, prioritizing them, and drafting a remediation-ready
change report - it does not compute the diff or decide pass/fail itself.

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


def extract_json(text: str) -> dict:
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
            "status": "pass" if passed else "FAIL",
        })
    return results


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
running config, (2) real DISA STIG rule pass/fail results already computed
- do not recompute or contradict these, your job is to explain and
prioritize, not re-check compliance.

For each drift and each STIG failure, explain the concrete security risk in
plain language, assign a severity (critical/high/medium/low), and where
relevant draft a one-line remediation command. Order your findings most
severe first, then write a 2-3 sentence executive summary.

Reply with ONLY JSON (no markdown fences):
{"executive_summary": "...", "findings": [{"item": "...", "severity": "...", "explanation": "...", "remediation": "..."}]}
"""


def main() -> None:
    client = AnthropicClient()

    baseline_text = (ROOT / "data" / "baseline_config.txt").read_text()
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    stig_rules = json.loads((ROOT / "data" / "stig_rules.json").read_text())

    diff = compute_diff(baseline_text, current_text)
    stig_results = check_stig_rules(current_text, stig_rules)
    interface_results = check_inactive_interfaces(current_text)

    print(f"Config diff: {len(diff)} line-level changes.")
    print(f"STIG checks: {sum(1 for r in stig_results if r['status'] == 'FAIL')}/{len(stig_results)} failed.")
    print(f"Interface checks: {sum(1 for r in interface_results if r['status'] == 'FAIL')}/{len(interface_results)} failed.\n")

    payload = {"config_diff": diff, "stig_rule_results": stig_results, "interface_results": interface_results}
    response = client.create(
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(payload, indent=2)}],
        max_tokens=3000,
    )
    text = "".join(b.text for b in response.content if b.type == "text")
    report = extract_json(text)

    print("=== Drift & Compliance Report ===\n")
    print(report["executive_summary"] + "\n")
    for f in report["findings"]:
        print(f"[{f['severity'].upper()}] {f['item']}")
        print(f"    {f['explanation']}")
        if f.get("remediation"):
            print(f"    Remediation: {f['remediation']}")
        print()


if __name__ == "__main__":
    main()

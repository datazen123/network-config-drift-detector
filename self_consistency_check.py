"""
Self-consistency check: does Claude assign the same severity to the same
finding across multiple independent samples of the same call?

Applies Wang, Wei, Schuurmans, Le, Chi, Narang, Chowdhery, Zhou,
"Self-Consistency Improves Chain of Thought Reasoning in Language Models"
(https://arxiv.org/abs/2203.11171, ICLR 2023) to this repo's
severity-assignment call: instead of trusting one sample, this calls it
`--samples` times (default 3) against the identical payload, then
deterministically majority-votes the severity for each finding - the same
"deterministic code owns the decision, Claude only proposes" split this
whole portfolio already uses, extended one level further: Claude proposes
N times, not once, and code picks the consensus.

This is additive - it doesn't change drift_detector.py's default
single-call behavior. It's a separate, live-measured test of how
consistent that call's severity judgment actually is, not a claim about
its accuracy.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python self_consistency_check.py [--samples N]
"""
from __future__ import annotations

import argparse
import json
from collections import Counter

from drift_detector import (
    ROOT, SYSTEM_PROMPT, build_payload, check_inactive_interfaces, check_stig_rules,
    compute_diff, extract_json, verify_findings,
)
from llm_client import AnthropicClient

DEFAULT_SAMPLES = 3


def sample_once(client: AnthropicClient, payload: dict, id_index: dict) -> dict:
    """One independent sample of the severity-assignment call, verified the
    same way the primary pipeline verifies it - a sample that fails
    verification (bad citation, severity/status contradiction, or a
    missing/wrong POA&M field) is excluded from voting, not silently
    counted."""
    response = client.create(
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(payload, indent=2)}, {"role": "assistant", "content": "{"}],
        max_tokens=3000,
    )
    text = "{" + "".join(b.text for b in response.content if b.type == "text")
    report = extract_json(text)
    findings = verify_findings(report["findings"], id_index)
    return {f["source_id"]: f for f in findings if f["verified"] and f.get("source_id")}


def majority_vote(severities: list[str]) -> tuple[str, bool]:
    """Deterministic aggregation - no LLM judgment. Returns the most common
    severity and whether it was unanimous across all samples given."""
    counts = Counter(severities)
    winner, count = counts.most_common(1)[0]
    return winner, count == len(severities)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    args = parser.parse_args()

    client = AnthropicClient()
    baseline_text = (ROOT / "data" / "baseline_config.txt").read_text()
    current_text = (ROOT / "data" / "current_config.txt").read_text()
    stig_rules = json.loads((ROOT / "data" / "stig_rules.json").read_text())

    diff = compute_diff(baseline_text, current_text)
    stig_results = check_stig_rules(current_text, stig_rules)
    interface_results = check_inactive_interfaces(current_text)
    payload, id_index = build_payload(diff, stig_results, interface_results)

    print(f"Sampling the severity-assignment call {args.samples} independent times "
          f"against the identical payload ({len(id_index)} citable items)...\n")

    samples = [sample_once(client, payload, id_index) for _ in range(args.samples)]

    all_source_ids = sorted({sid for s in samples for sid in s})
    results = {}
    for source_id in all_source_ids:
        severities = [s[source_id]["severity"] for s in samples if source_id in s]
        if len(severities) < args.samples:
            results[source_id] = {
                "severities_by_sample": severities,
                "consensus": None,
                "unanimous": False,
                "note": f"only {len(severities)}/{args.samples} samples produced a verified "
                        f"finding for this id",
            }
            continue
        winner, unanimous = majority_vote(severities)
        results[source_id] = {"severities_by_sample": severities, "consensus": winner, "unanimous": unanimous}

    unanimous_count = sum(1 for r in results.values() if r["unanimous"])
    total = len(results)

    print("=== Self-consistency results ===\n")
    for source_id, r in results.items():
        if r["consensus"] is None:
            tag = "INCOMPLETE"
        elif r["unanimous"]:
            tag = "UNANIMOUS"
        else:
            tag = "SPLIT"
        print(f"[{tag}] {source_id}: {r['severities_by_sample']} -> consensus: {r['consensus']}")

    complete = [r for r in results.values() if r["consensus"] is not None]
    print(f"\nFindings present in all {args.samples} samples: {len(complete)}/{total}")
    print(f"Unanimous agreement among those: {unanimous_count}/{len(complete)} "
          f"({round(100 * unanimous_count / len(complete)) if complete else 0}%)")

    (ROOT / "self_consistency_result.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Wrote self_consistency_result.json")


if __name__ == "__main__":
    main()

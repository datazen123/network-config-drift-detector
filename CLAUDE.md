# Context for Claude Code working in this repo

This repo is one of a **10-repo public portfolio** (github.com/datazen123)
demonstrating real, live-verified agentic AI engineering for a specific
DoD-contractor job pursuit. Full README below covers this repo in detail;
this file covers conventions and status a coding agent needs before making
changes.

## This repo's role

Deterministic Cisco IOS config diff + real DISA STIG compliance checks +
a DISA-severity-weighted compliance scorecard + real NIST 800-53/CCI
control mapping + Claude-drafted POA&M-style remediation milestones.
Claude explains/prioritizes and cites a `source_id`; `verify_findings()`
checks citations resolve and don't contradict the underlying pass/FAIL
status or severity-to-POA&M-priority mapping, with one bounded correction
pass.

**Status (2026-07-27)**: 31/31 tests passing (including Hypothesis
property-based tests proving the compliance score stays in [0,100] and
never increases when a passing check flips to FAIL), live-verified. Every
STIG rule now carries its real CAT I/II/III severity and real CCI/NIST
800-53 control ID (verified against cyber.trackr.live - two secondary
sources disagreed on one rule's severity during verification, resolved
against the primary source). CI runs pytest + bandit (non-blocking on
low-severity findings).

## Non-negotiable discipline this whole portfolio follows

1. Never fabricate a source - every real-data claim is independently
   fetched/verified. If a primary source can't be reached, say so plainly
   rather than guess.
2. Deterministic code owns any mechanical computation/decision; Claude
   only handles the genuinely ambiguous/language part.
3. Live-verify against the real Anthropic API before claiming a result -
   report actual measured numbers, including when they're unflattering.
4. Synthetic demo data is always labeled as synthetic; real external data
   is cited with exact source/rule IDs.
5. Every repo has a pytest suite (Hypothesis property-based tests where
   present), GitHub Actions CI (pytest + bandit), a "Security notes"
   README section, and pinned dependencies.
6. No real client, unit, or classified-sounding content ever.
7. Ask Sage (not Claude directly) is named as the realistic DoD/DIB
   production deployment path in every repo's README.
8. This repo's own README states the DISA-weighted scorecard is a
   defensible illustrative model built on real severity data - it is NOT
   a reproduction of DISA's actual (non-public) CCRI grading algorithm.
   Keep that distinction precise if extending this further.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY, never commit it
pytest -q
```

Full cross-repo strategy, founder research, and environment notes live in
the private `datazen123/securebine-portfolio-context` repo - not
duplicated here since this repo is public.

# network-config-drift-detector

Deterministic code computes the line-level diff between a baseline and
current Cisco IOS-style router config, and checks the current config
against real DISA Cisco IOS Router STIG rules - including each rule's real
CAT I/II/III severity rating - to compute a weighted compliance scorecard.
Claude's job is the part that's actually a language task: explaining the
semantic risk of each drift and STIG failure, prioritizing them, and
drafting a remediation-ready report with POA&M-style milestones - it never
computes the diff, the score, or decides pass/fail itself.

## Compliance scorecard and POA&M drafting

Every STIG rule in `data/stig_rules.json` now carries its real CAT I/II/III
severity rating, verified directly against
[cyber.trackr.live](https://cyber.trackr.live/stig/Cisco_IOS_Router_NDM/2/8)'s
published Cisco IOS Router NDM STIG data (two independent secondary sources
disagreed on one rule's severity during this verification - resolved
against the primary source rather than either guess). `compute_compliance_score()`
turns open findings into a weighted 0-100 score using those real severity
ratings.

**Said precisely, not oversold**: DISA's actual internal CCRI grading
methodology isn't fully public, so this is *not* a reproduction of it - the
severity data feeding the score is real and verified; the point-deduction
weights on top of it (CAT I costs more than CAT II) are a defensible,
clearly-labeled illustrative model, the same "real data, honestly-labeled
logic on top" split this repo's interface-shutdown check already uses.

For every failed check, Claude also drafts a short POA&M-style entry
(milestone + priority tier - immediate/30-day/90-day, mapped directly from
the real CAT rating) - the same category of artifact a real RMF/eMASS
Plan of Action and Milestones uses, though not literally eMASS-formatted
output. `verify_findings()` now checks two more things deterministically:
every failed-check finding has a non-empty milestone, and its priority tier
matches what the real severity rating requires (CAT I → immediate) -
findings that get this wrong are flagged the same
`[NEEDS HUMAN VERIFICATION]` way as a bad citation.

## Why this exists

Grounded in real federal award data, verified via USASpending.gov (not
just press/web claims), plus SecureBine's own public statements, with one
signal below that's directionally real but not yet independently
confirmed in award data:

- **Confirmed, recurring, Korea-specific**: IDIQ `W91QVN17D0038` covers
  CCTV/physical-security-network maintenance task orders at Camp
  Humphreys and Area IV (Daegu) - real, dated, small-firm (SM Global,
  Cydaptiv Solutions, Image & Information Co., EC Control) task orders in
  exactly this repo's category: monitoring and maintaining a network of
  security-relevant infrastructure. This is the strongest single piece of
  confirmed evidence behind this repo.
- **Reported but not independently verified**: the Army's Empower AI-led
  **Army Transport Edge (ATE)** modernization (~$27-40M, software-defined
  networking across 52 Korea sites) is corroborated by Empower AI's own
  press release and Stars and Stripes (Feb 2026, "nearly complete," full
  legacy cutover targeted Sept 26, 2026) - but a direct USASpending search
  could not locate the underlying award record, and **no follow-on
  operations/monitoring contract has been posted on SAM.gov** as of a July
  2026 check. This repo anticipates that need ahead of the cutover date,
  it doesn't point to an already-funded one.
- **SecureBine's own public announcement**: SecureBine has publicly
  confirmed a multi-year IDIQ services contract supporting USACISA-P
  requirements at Camp Humphreys, in partnership with GovCIO - matching
  GovCIO's own stated USACISA-P scope ("service and maintain all IT and
  network services across the coalition network, CENTRIXS-K"). This
  doesn't yet appear in USASpending's prime/subaward data (a normal
  award-to-posting lag, not a reason to doubt a company's own public
  statement about its own contract). (Also confirmed, same program: SAIC
  and GDIT hold/held the actual USACISA-P network-operations task orders
  - see `claude-ops-agent`.)
- SecureBine's own certified technology partnerships are **Cisco and
  Juniper** specifically - this repo's actual named vendor, not an
  adjacent guess (this one is a direct fact about SecureBine's public
  site, not something that needs award-data verification).

## What's real vs. illustrative

- `data/stig_rules.json` - **real** DISA Cisco IOS Router STIG rules,
  fetched from public STIG reference content (rule IDs V-215687, V-215669,
  V-215668, V-215699, V-215704 from the Cisco IOS Router NDM STIG, V3R8):
  exact rule ID, title, requirement text, fix guidance, real CAT I/II/III
  severity rating (V-215687 and V-215699 are CAT I; the rest are CAT II),
  and each rule's real CCI ID and NIST SP 800-53 Rev 5 control mapping
  (e.g. V-215687 → CCI-000196 → **IA-5**), verified against
  [cyber.trackr.live](https://cyber.trackr.live/stig/Cisco_IOS_Router_NDM/2/8).
  This is the actual traceability chain a real RMF/eMASS package uses -
  STIG finding → CCI → 800-53 control - not something this repo invented;
  every finding in the printed report now cites the real control ID
  alongside the STIG rule.
- `data/baseline_config.txt` / `data/current_config.txt` - **illustrative**,
  synthetic Cisco IOS-syntax configs written for this demo, not captured
  from any real device. Not every real STIG check is implemented -
  `check_inactive_interfaces()` is an explicitly-documented simplification
  (config-text-only proxy for "interface should be inactive," not the
  official check procedure, which also considers live operational status).

## Architecture

```
data/baseline_config.txt   data/current_config.txt   data/stig_rules.json
        |                          |                          |
        v                          v                          v
  compute_diff()          check_stig_rules() +      (real STIG rule IDs
  (difflib, code-owned)   check_inactive_interfaces()   and requirements)
        |                          |
        +--- build_payload(): every item gets a stable id (diff:N, ---+
             stig:<rule_id>, interface:<name>) ---+
                       |
                       v
              Claude explains, prioritizes, drafts remediation commands,
              and cites a source_id on every finding
                       |
                       v
              verify_findings() - deterministic, code-owned: does each
              source_id resolve? does severity contradict a passing check?
                       |
              +--------+--------+
              v                 v
      all findings verified   any flagged -> ONE bounded correction pass
              |                 (Claude fixes only the flagged findings)
              v                 v
              +--- printed report, unverified findings tagged ---+
                    "[NEEDS HUMAN VERIFICATION]"
```

## Closing the loop on a real, previously-honestly-reported limitation

Earlier versions of this repo's README documented a real, live-observed
failure mode: Claude occasionally blended details between two nearby,
related config changes in its prose explanation - e.g. attributing an
interface description change to the wrong interface ID - even though the
underlying deterministic classification stayed correct. That was being
caught by manual read-through, which doesn't scale and isn't something a
DoD-adjacent client would accept as the actual safeguard.

`verify_findings()` (pure Python, fully unit-tested, no LLM call) now checks
two things deterministically for every finding Claude writes: (1) does its
`source_id` actually resolve to a real diff line, STIG rule, or interface
from the data Claude was given - this is exactly the class of error the
blending bug produced, since a blended finding cites (or fails to cite) the
wrong thing; and (2) does the claimed severity contradict the item's actual
status (e.g. `critical` severity cited against something that actually
passed). Anything flagged gets one bounded correction pass - Claude is
shown only the flagged findings plus the original data and asked to fix
just those - before the report is finalized. Findings still flagged after
that correction pass are printed with an explicit
**`[NEEDS HUMAN VERIFICATION]`** tag rather than presented as equally
reliable, so a reviewer knows exactly which lines earned a second look and
which didn't.

This is the same evaluator-optimizer / reflection pattern used in
`claude-ops-agent`'s bounded tool-call retry, applied to content
verification instead of format enforcement - grounded in the DoD's
published **Traceable** AI Ethical Principle (see that repo's README for
the full citation): every finding is auditable back to the exact
deterministic fact it's about, in code, not by asking a human to eyeball
the whole report.

- `llm_client.py` - thin provider adapter. Anthropic is the tested backend
  used throughout this repo. OpenAI and Ask Sage adapters are included for
  the same interface, but have **not** been run against live credentials in
  this repo - treat them as reference code until verified.
- `drift_detector.py` - the diff, the STIG/interface checks, the payload
  id-tagging (`build_payload`), the Claude explanation call, the
  deterministic verifier (`verify_findings`), and the bounded correction
  pass.

## Running it

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
python drift_detector.py
```

## Tests + CI

`test_drift_detector.py` covers every deterministic function (the diff,
both STIG check types, the interface check, JSON-fence stripping,
`build_payload`'s id-tagging, `compute_compliance_score`'s weighting and
zero-floor behavior, and every branch of `verify_findings` - missing
citation, unresolvable citation, severity/status contradiction, missing
POA&M milestone, wrong POA&M priority tier, and the passing case) - no API
key or network needed, safe for CI on every push. `test_drift_detector_properties.py`
adds Hypothesis property-based tests - e.g. the compliance score is proven
to stay in [0,100] and never increase when a passing check flips to FAIL,
across hundreds of generated severity-mix inputs, not one hand-picked
example:

```bash
pip install -r requirements-dev.txt
pytest -q
bandit -r . -x "./.venv" --severity-level medium  # security lint, CI runs this too
```

## Security notes

- API keys are read from environment variables only, never hardcoded;
  `.env` is gitignored, `.env.example` ships placeholders only.
- Network calls to the Ask Sage gateway have explicit 30s timeouts from
  the start (not retrofitted).
- A malformed/non-JSON model response raises a clear, actionable error
  (with the raw response attached) instead of an opaque traceback.
- Dependencies are version-pinned with an upper bound (`>=X,<NEXT_MAJOR`).
- `OpenAIClient` checks for its API key before importing the `openai`
  package, not after - a guard-clause-ordering bug found (and fixed
  retroactively) in every other repo in this portfolio; built correctly
  here from the start.

## Deployment path

This demo calls the Anthropic API directly. A production version for a
DoD-adjacent client would more likely run through
**[Ask Sage](https://www.asksage.ai/)** - the IL5/IL6-authorized multi-model
gateway built for Defense Industrial Base contractors (`llm_client.py`
includes an `AskSageClient` built from Ask Sage's
[public API docs](https://github.com/Ask-Sage/AskSage-Open-Source-Community),
untested pending an account).

Built with [Claude Code](https://claude.com/claude-code).

# network-config-drift-detector

Deterministic code computes the line-level diff between a baseline and
current Cisco IOS-style router config, and checks the current config
against real DISA Cisco IOS Router STIG rules. Claude's job is the part
that's actually a language task: explaining the semantic risk of each
drift and STIG failure, prioritizing them, and drafting a
remediation-ready report - it never computes the diff or decides
pass/fail itself.

## Why this exists

Three concrete, current signals pointed here, not at a generic "AI +
networking" idea:

- The Army's Empower AI-led **Army Transport Edge (ATE)** modernization -
  a real ~$40M effort introducing software-defined networking across 52
  sites in South Korea - was reported by Stars and Stripes as "nearly
  complete" in February 2026. A major network modernization that just
  finished creates a near-term, predictable need: monitoring and
  drift-detection on the network that was just stood up.
- **GovCIO's own confirmed scope on USACISA-P** (the U.S. Army
  Communication Information Systems Activity-Pacific program serving
  UNC/CFC/USFK - the same contract vehicle referenced elsewhere in this
  portfolio) is "service and maintain all IT and network services across
  the coalition network, CENTRIXS-K." Network config monitoring sits
  inside that scope directly.
- SecureBine's own certified technology partnerships are **Cisco and
  Juniper** specifically - this repo's actual named vendor, not an
  adjacent guess.

## What's real vs. illustrative

- `data/stig_rules.json` - **real** DISA Cisco IOS Router STIG rules,
  fetched from public STIG reference content (rule IDs V-215687, V-215669,
  V-215668, V-215699, V-215704 from the Cisco IOS Router NDM STIG, V3R8):
  exact rule ID, title, requirement text, and fix guidance.
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
        +------------ combined ---+
                       |
                       v
              Claude explains, prioritizes,
              and drafts remediation commands
                       |
                       v
              printed drift & compliance report
```

## A real, honestly-reported limitation

Across live runs, Claude occasionally blends details between two nearby,
related config changes when synthesizing its prose explanation - e.g.
attributing an interface description change to the wrong interface ID,
even though the underlying deterministic classification (which STIG rule
failed, which interface is non-compliant) stays correct. This is reported
rather than hidden: the structured findings (severity, rule ID,
remediation command) are reliable; the free-text explanation occasionally
needs a human sanity-check on cross-references between findings.

- `llm_client.py` - thin provider adapter. Anthropic is the tested backend
  used throughout this repo. OpenAI and Ask Sage adapters are included for
  the same interface, but have **not** been run against live credentials in
  this repo - treat them as reference code until verified.
- `drift_detector.py` - the diff, the STIG/interface checks, and the
  Claude explanation call.

## Running it

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
python drift_detector.py
```

## Tests + CI

`test_drift_detector.py` covers every deterministic function (the diff,
both STIG check types, the interface check, JSON-fence stripping) - no
API key or network needed, safe for CI on every push:

```bash
pip install -r requirements-dev.txt
pytest -q
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

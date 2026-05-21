# Lurkr Agent Notes

Follow the canonical AVP instructions in `/Users/olegboiko/Desktop/AVP/AGENTS.md`.
The rules below are additional and stricter where applicable.

## Project Scope

Lurkr is the posture scanner and GitHub Action for identifying risky repository
and workflow patterns. Treat scanner findings, policy behavior, and action
outputs as security-sensitive surfaces.

## Build and Test

```bash
python -m pip install -e ".[test]"
python -m pytest
```

Run targeted CLI or action smoke checks when changing scanner behavior,
fixtures, report formats, or GitHub Action inputs/outputs.

## CI Policy

Follow [`docs/CI_POLICY.md`](docs/CI_POLICY.md).

- Run relevant local tests before pushing code changes.
- The push fast gate is not release verification.
- The full OS/Python compatibility gate and action smoke gate must pass before
  release tags or Docker publication.
- Do not use `[skip ci]` for code, packaging, security, or behavior changes.
- When reporting done, state the local commands and CI gates that actually ran.

## Security Discipline

- Do not commit secrets, private URLs, private customer data, or generated
  credentials.
- Treat workflow parsing, action behavior, and scanner output schemas as trust
  boundaries.
- For security-bearing changes, test both expected detections and expected
  non-detections.
- Keep changes narrow; do not bundle unrelated scanner, packaging, and
  documentation changes.

## Quality Tripwire for Risky Changes

Apply this only to behavior-changing, security-relevant, release-impacting, or
rule-detection changes. Do not require it for trivial docs/hygiene edits.

Before implementation or in the review packet, include a short block:

- Invariant: one sentence describing the behavior that must hold.
- Fails-before test: the risky or bypass case that would fail before the fix
  and pass after it.
- Safe/control test: the legitimate case that must not regress.
- Residual risk: 1-3 concrete things still not covered or intentionally out of
  scope.
- Checks: targeted test, full test, validation harness, docs/public scan, or
  other relevant commands.

For detection/suppression rules:

- Always add a bypass/FN regression test and a safe/FP control test.
- Do not treat broad document-text markers as approval/suppression unless the
  rule explicitly scopes them to the risky object.
- Cat 1 validation must include at least one labeled fixture for the bypass
  class fixed or added.

For remediation docs:

- Bad examples should trigger the documented rule.
- Good examples must not trigger the rule they document.
- If a good example uses an approval marker that only affects another rule, say
  so or remove it.

Before commit:

- Run `git diff --check`.
- Run targeted tests for touched behavior.
- Run full pytest for rule/runtime/security changes.
- Run the validation harness for rule behavior changes.
- Run public-surface term/link checks for README/docs/release-surface changes.

Engineering rule: green tests are not enough unless the packet can name the
invariant they prove.

## Reviewer Evidence Sanity Check

Codex is not the reviewer of the reviewer. Do not re-review every approval.

However, before acting on a reviewer approval for behavior-changing,
security-relevant, release-impacting, or Cat 1 rule changes, do a quick sanity
check that the approval includes at least minimal evidence.

Sufficient evidence can be any 2-3 of:

- exact files or diffs reviewed;
- exact tests/checks independently run;
- explicit invariant or bypass path verified;
- labeled validation/harness result checked;
- concrete residual risks or non-blocking observations.

If the approval is only generic, such as "LGTM", "looks good", "tests pass", or
"approved" with no concrete evidence, do not proceed to commit/release. Ask one
concise clarification:

"Before I act on this approval, can you confirm which files/tests/invariant you
verified? This is a Cat 1/security-sensitive change."

Avoid ping-pong:

- Ask at most once.
- If the operator explicitly overrides and says to proceed, proceed.
- For docs-only/Cat 3 changes, do not block on this unless the review is
  obviously inconsistent with the diff.
- Do not perform a second full review yourself unless the operator asks.

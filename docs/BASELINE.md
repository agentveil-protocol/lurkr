# Lurkr Baseline Mode

Lurkr's `--baseline` flag lets teams adopt the scanner on existing repositories
without turning every existing finding into immediate CI noise.

The workflow:

1. Run Lurkr once and save the current findings:

   ```bash
   lurkr scan --path . --save-baseline .lurkr-baseline.json
   ```

2. Commit `.lurkr-baseline.json` to the repository.

3. Run Lurkr in CI with the baseline:

   ```bash
   lurkr scan --path . --baseline .lurkr-baseline.json --fail-on high
   ```

From that point on, Lurkr reports only new findings. Findings already present
in the baseline are grandfathered until the team chooses to address or refresh
them.

## Saving a Report and a Baseline

`--save-baseline` can be used without `--output` when you only want the
baseline file. To write both the normal report and the baseline:

```bash
lurkr scan --path . --output lurkr-report.json --save-baseline .lurkr-baseline.json
```

`--baseline` and `--save-baseline` are mutually exclusive in one invocation.
Use one command to create or refresh the baseline, and another command to apply
it.

## When to Re-Baseline

Update the baseline when:

- You have intentionally addressed existing findings and want the file to
  reflect the remaining accepted review surface.
- Refactoring shifts file names, variable names, or message text enough to make
  old fingerprints drift.
- You intentionally accept a new finding after review and want future CI runs
  to treat it as known.

To refresh:

```bash
lurkr scan --path . --save-baseline .lurkr-baseline.json
```

Review the baseline diff before committing it. A large unexpected change can
mean rules changed, files moved, or the scan path is different.

## Fingerprint Stability

Lurkr fingerprints findings with SHA-256 over:

```text
rule_id + relative_path + redacted_message
```

This is stable across:

- Line-number shifts when code is inserted above a finding.
- Edits elsewhere in the same file.
- Report timestamp changes.

Fingerprints drift if you:

- Rename variables that appear in finding messages.
- Rename or move the file.
- Upgrade to a Lurkr version that changes a rule's message wording.

When drift occurs, the old finding appears as new in the next scan. Review the
finding and re-baseline if the risk is still accepted.

## What Baseline Does Not Do

- It does not fix findings; it only suppresses known fingerprints from the
  report.
- It does not classify findings as safe or unsafe. That remains a human review
  decision.
- It does not migrate findings across rule-message changes.
- It does not report findings removed since the baseline. Re-run
  `--save-baseline` when you want to refresh the accepted set.

Baseline mode is an adoption tool, not a waiver system. Keep the baseline file
small over time by fixing or removing accepted findings when practical.

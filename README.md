# AgentVeil Posture

AgentVeil Posture is a static, local scanner for risky agent capabilities.
v0.1 focuses on GitHub-oriented posture checks and produces a redacted JSON
report.

v0.1 checks are best-effort static heuristics. They are intended to highlight
review-worthy agent posture risks, not to replace code review, SAST, or secret
scanning.

## Install

Local development:

```bash
pip install -e .
```

GitHub-only install after v0.1.0 is tagged:

```bash
pip install git+https://github.com/agentveil-protocol/agentveil-posture@v0.1.0
```

PyPI publishing is out of scope for v0.1.

## GitHub Action

Use the action from the same repository after `v0.1.0` is tagged:

```yaml
- uses: agentveil-protocol/agentveil-posture@v0.1.0
  with:
    path: "."
    output: agentveil-posture-report.json
```

The action requires Python 3.10 or newer on the runner. It writes the JSON
report path to the `report` output and does not upload data to AgentVeil.

## Usage

```bash
agentveil posture scan --path . --output report.json
```

The v0.1 CLI exposes `posture scan` only. There is no `check` alias in v0.1.

## v0.1 Detection Scope

All v0.1 rules are high severity:

- `bypass.direct_github_token`
- `workflow.deploy_without_approval`
- `workflow.pull_request_target_secrets_risk`
- `tool.shell_without_approval`
- `identity.private_key_unencrypted`

The v0.1 scanner is static and heuristic. Findings are intended to identify
review-worthy posture risks, not to prove exploitability.

## Hard Constraints

The scanner is designed to be:

- offline by default, with no network calls;
- telemetry-free;
- read-only against the scanned project;
- static-only, with no scanned code execution;
- secret-safe, reporting only redacted findings.

Private-key checks use file metadata and bounded header sniffing only. Reports
must not include raw private key bytes or secret values.

## Dependency Policy

The package uses the Python standard library plus `PyYAML>=6.0.1,<7` for
deterministic GitHub workflow and manifest parsing. Additional runtime
dependencies require explicit justification.

## Known Limitations

- v0.1 is a best-effort heuristic scanner and may produce false positives or
  false negatives.
- Parser-rejected files are skipped without per-file skip reasons in the JSON
  report.
- The dangerous fixture includes an intentional synthetic PEM-shaped file for
  rule testing. It does not contain a real key.

## License

MIT. See `LICENSE`.

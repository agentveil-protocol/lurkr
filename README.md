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

The package uses the Python standard library plus `PyYAML` for deterministic
GitHub workflow parsing. Additional runtime dependencies require explicit
justification.

## License

MIT. See `LICENSE`.

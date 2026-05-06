# AgentVeil Posture

```text
  +----------+      +----------+      +----------+
  |   FIND   |      |  DECIDE  |      |  PROVE   |
  |  risky   | ---> |  what is | ---> |  what    |
  |   caps   |      |  allowed |      | happened |
  +----------+      +----------+      +----------+
   you are here       roadmap          roadmap
   v0.1 Posture
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/agentveil-protocol/agentveil-posture?style=for-the-badge&logo=github&color=gold)](https://github.com/agentveil-protocol/agentveil-posture/stargazers)
[![GitHub Action](https://img.shields.io/badge/GitHub-Action_ready-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](#use-as-a-github-action)
[![Posture: read-only](https://img.shields.io/badge/scanner-read--only-10b981?style=for-the-badge)](#hard-constraints)

**Pre-deployment posture check for AI agents. Find risky capabilities before they become production incidents.**

`agentveil-posture` is a pre-deployment, static, local-only scanner that flags
risky AI-agent and GitHub-workflow posture issues. No telemetry, no network
calls, no project code execution. v0.1 ships five high-severity GitHub-focused
rules.

[Quick Start](#quick-start) |
[What a finding looks like](#what-a-finding-looks-like) |
[Detection scope](#detection-scope-v01) |
[GitHub Action](#use-as-a-github-action) |
[Why this exists](#why-this-exists)

---

## Quick Start

```bash
pip install git+https://github.com/agentveil-protocol/agentveil-posture@v0.1.0
agentveil posture scan --path . --output report.json
cat report.json
```

That is the whole flow. The scanner is read-only: it does not modify your
files, run your code, or send data over the network.

## What a Finding Looks Like

```json
{
  "rule_id": "workflow.deploy_without_approval",
  "severity": "high",
  "file": ".github/workflows/deploy.yml",
  "line": 12,
  "message": "Deployment workflow appears to run without an approval gate.",
  "remediation": "Add a protected GitHub environment or explicit manual approval before production deploy, release, or publish steps."
}
```

Every finding contains rule ID, severity, repository-relative file path, line
number when available, redacted message, and remediation pointer. Raw secrets,
command bodies, and key material never appear in the report.

## Detection Scope (v0.1)

All v0.1 rules are reported as `high` severity.

| Rule | What it flags |
|---|---|
| `bypass.direct_github_token` | Direct GitHub PAT/token references in workflows or agent manifests |
| `workflow.deploy_without_approval` | Deploy/release/publish steps without an approval gate |
| `workflow.pull_request_target_secrets_risk` | `pull_request_target` workflows that combine privileged context with checkout, run, or secrets |
| `tool.shell_without_approval` | Agent tool manifests that enable shell execution without an approval flag |
| `identity.private_key_unencrypted` | Unencrypted PEM private key files committed to the repo |

## Install

<details>
<summary><b>From GitHub release (recommended)</b></summary>

```bash
pip install git+https://github.com/agentveil-protocol/agentveil-posture@v0.1.0
```

</details>

<details>
<summary><b>From source (development)</b></summary>

```bash
git clone https://github.com/agentveil-protocol/agentveil-posture
cd agentveil-posture
pip install -e .
```

</details>

<details>
<summary><b>PyPI</b></summary>

PyPI publication is not available in v0.1.0. Use the GitHub install URL above.

</details>

## Use as a GitHub Action

Use the action from the same repository:

```yaml
- uses: agentveil-protocol/agentveil-posture@v0.1.0
  with:
    path: "."
    output: agentveil-posture-report.json
```

The action requires Python 3.10 or newer on the runner. It writes the JSON
report path to the `report` output and does not upload data to AgentVeil.

## Why This Exists

AI agents increasingly touch production credentials, deploy workflows, and
developer infrastructure. AgentVeil Posture is the first step: find risky
capabilities before runtime, before deployment, and before they become
incidents.

| | Posture does | Posture does not |
|---|---|---|
| Scope | Static analysis and posture risk patterns | Runtime control or policy enforcement |
| Effects | Read-only file inspection | Code execution, network calls, or file mutation |
| Output | Redacted JSON findings | Secret values, command bodies, or key bytes |

For runtime control of agent actions, see the broader
[AgentVeil project](https://agentveil.dev).

## Hard Constraints

The scanner is designed to be:

- **offline**: no network calls
- **telemetry-free**: no usage data collected
- **read-only**: does not modify scanned files
- **static-only**: does not execute scanned project code
- **secret-safe**: reports only redacted findings

Private-key checks use file metadata and bounded header sniffing only.

## Dependency Policy

Runtime dependencies are intentionally minimal:

- Python `>=3.10`
- `PyYAML>=6.0.1,<7`

Additional runtime dependencies require explicit justification in
[PLAN.md](PLAN.md).

## Known Limitations

`agentveil-posture` v0.1 is a best-effort heuristic scanner, not an exhaustive
security audit.

- Some rules may produce false positives or false negatives.
- Oversized, unreadable, or malformed inputs may be skipped without per-file
  skip reasons.
- YAML parsing is bounded, but carefully crafted YAML within the v0.1 alias
  limit can still consume parser memory.
- The repository includes an intentional synthetic PEM-shaped fixture for
  scanner tests. It is not a real private key.

## Community

- [Star this repo](https://github.com/agentveil-protocol/agentveil-posture/stargazers)
  if Posture helps your team.
- [Open an issue](https://github.com/agentveil-protocol/agentveil-posture/issues)
  for bugs, false positives, or rule suggestions.
- See [PLAN.md](PLAN.md) for the v0.1 spec, schema details, and v0.2 backlog.

## License

MIT. See [LICENSE](LICENSE).

---

Part of the [AgentVeil project](https://agentveil.dev): action control for
autonomous agents.

# Lurkr

**Find what your agent can touch before you deploy it.**

Lurkr is a pre-deployment, static, local-only scanner that flags risky
AI-agent and GitHub-workflow capability issues. No telemetry, no network
calls, no project code execution. Reports are redacted by default.

## Quick Start

```bash
pip install lurkr
lurkr scan --path . --output report.json
cat report.json
```

To fail CI when findings meet a threshold:

```bash
lurkr scan --path . --output report.json --fail-on high
```

## Current Scope

v0.2 includes ten high-severity rules across GitHub workflows, agent manifests,
identity files, and bounded Python agent-source analysis.

Lurkr is read-only, offline, telemetry-free, and static-only. It does not
modify scanned files, execute project code, or send repository data over the
network.

## Links

- Repository: https://github.com/agentveil-protocol/lurkr
- Documentation: https://github.com/agentveil-protocol/lurkr#readme
- Issues: https://github.com/agentveil-protocol/lurkr/issues

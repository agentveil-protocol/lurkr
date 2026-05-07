# AgentVeil Posture Validation Harness

This directory contains the Cat 1 labeled validation harness for public rule
changes. It is separate from unit tests: unit tests check local invariants, while
validation compares scanner output against pinned labels.

## Run

```bash
LANGCHAIN_ROOT=/tmp/posture-smoke-langchain \
LANGGRAPH_ROOT=/tmp/posture-smoke-langgraph \
CREWAI_EXAMPLES_ROOT=/tmp/posture-smoke-crewai-examples \
MCP_SERVERS_ROOT=/tmp/posture-smoke-mcp-servers \
ANTHROPIC_SDK_PYTHON_ROOT=/tmp/posture-smoke-anthropic-sdk-python \
AGENTVEIL_MCP_DOGFOOD_ROOT=/path/to/avp-sdk-public \
python validation/run.py
```

If an external checkout env var is omitted, the harness clones the public repo
to `/tmp/agentveil-posture-validation` and checks out the pinned commit. The
AVP SDK dogfood label uses the env var when the repo is not publicly cloneable.
The corpus also includes two in-repository calibration labels for synthetic
fixtures that cover rules unlikely to appear safely in public examples, such as
unencrypted private key detection.

## Label Schema

Each `validation/labels/*.json` file has:

```json
{
  "repo": "owner/repo",
  "commit": "pinned-sha-or-WORKTREE",
  "scan_path": "path/inside/checkout",
  "checkout_env": "OPTIONAL_LOCAL_CHECKOUT_ENV",
  "expected_findings": [
    {"rule_id": "agent.python_tool_without_approval", "file": "tool.py", "line": 42}
  ],
  "rules_that_should_not_fire_in_this_repo": [
    "identity.private_key_unencrypted"
  ]
}
```

`file` is the repo-relative POSIX path emitted by the scanner for the configured
`scan_path`. In-repository fixtures use `commit: "WORKTREE"` because a Git commit
cannot self-reference the hash that contains its own labels.

## Thresholds

Default thresholds are per rule:

- precision >= 0.85
- recall >= 0.80

Precision is `true_positive / observed`. Recall is `true_positive / expected`.
Rules with no expected and no observed findings score `1.0`, but Cat 1 validation
also requires positive expected coverage for every active rule.

The harness exits non-zero when a threshold is breached, a forbidden rule fires,
an active rule lacks positive label coverage, or scaffold labels are still empty.

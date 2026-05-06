# AgentVeil Posture v0.1 Plan

Status: Day 1 plan/spec for Phase 1 Sprint 1.

Scope: plan and repo skeleton only. Rule detection, dangerous fixture content,
`action.yml`, publishing, remote creation, and GitHub push are out of scope for
Day 1.

## Product Boundary

AgentVeil Posture v0.1 is a local, static scanner for GitHub-focused agent
posture risks. It helps teams find risky capabilities before production use.

Hard constraints:

- zero network calls;
- zero telemetry;
- no file mutation inside the scanned project;
- no code execution from the scanned project;
- no shell, package-manager, Docker, Git, or subprocess execution during scan;
- no secrets handling beyond metadata and bounded header sniffing;
- no raw secret values in findings, reports, logs, or GitHub Action summaries.

Phase 1-2 public wording must not claim production controlled execution is live.
Production Gateway enforcement remains roadmap until separately shipped.

## Architecture

Package layout:

```text
agentveil-posture/
  pyproject.toml
  src/agentveil_posture/
    __init__.py
    cli.py
    report.py
    scanner.py
    rules/
      __init__.py
  tests/
  fixtures/
    clean_github_project/
    dangerous_github_project/
```

Data flow:

```text
agentveil posture scan
  -> cli.parse_args()
  -> scanner.scan_path(path)
  -> scanner discovers bounded, static file candidates
  -> rules registry evaluates GitHub workflow/tool/identity rules
  -> report.PostureReport is built with redacted findings only
  -> reporter writes stable JSON to --output
  -> cli returns exit code according to v0.1 rules
```

Module responsibilities:

- `cli.py`: owns argparse commands and exit-code mapping. v0.1 exposes only
  `agentveil posture scan --path . --output report.json`.
- `scanner.py`: orchestrates static discovery, applies rule registry, enforces
  hard constraints, and returns a report model.
- `rules/__init__.py`: owns the v0.1 rule registry. Individual rule modules may
  be split out on Day 2 if clearer.
- `report.py`: owns versioned dataclasses and JSON serialization. It must never
  include raw secret values or source snippets.

Dependency policy:

- Standard library first.
- `PyYAML` is the only planned runtime dependency, justified by deterministic
  parsing of GitHub workflow YAML files.
- YAML parsing must use `yaml.safe_load` only. `yaml.load`, custom object
  constructors, and arbitrary Python-object deserialization are forbidden
  because scanned repository YAML is untrusted input.
- GitHub workflow YAML must be size-capped before parsing and rejected if alias
  usage exceeds the v0.1 parser limit. Alias-heavy YAML must be rejected before
  object expansion.
- If Day 2 can implement workflow parsing safely without YAML parsing, remove
  `PyYAML` before release.

## Static Candidate Discovery

The scanner must use deterministic, bounded discovery. It must not execute
package managers, shell scripts, hooks, Git commands, or project imports.

Shared candidate rules for v0.1:

- GitHub workflow rules inspect only `.github/workflows/*.yml` and
  `.github/workflows/*.yaml`.
- Agent/tool manifest rules inspect only pinned agent-manifest formats:
  `.mcp.json`, `.cursor/mcp.json`, `mcp.json`, `mcp_config.json`,
  `crew*.yaml`, `crew*.yml`, `autogen*.json`, `autogen*.yaml`,
  `langchain*.json`, and `langchain*.yaml`.
- Generic files such as `Makefile`, `package.json` scripts, `shell.nix`,
  Dockerfiles, arbitrary source code, and general CI commands are not v0.1
  agent-tool candidates unless a later approved rule explicitly adds them.
- Identity rules may inspect any regular file through file metadata and a
  bounded header prefix only.
- Symlinks are skipped in v0.1, including symlinks that point inside the scan
  root. Outside-root symlinks must never be followed.
- Finding file paths are repository-relative POSIX paths under `scanned_path`,
  never absolute paths.

## Rules v0.1

All v0.1 rules have severity `high`.

### `bypass.direct_github_token`

Reads:

- GitHub workflow YAML files under `.github/workflows/`;
- the pinned agent/tool manifest candidates listed in
  `Static Candidate Discovery`.

Matches:

- direct references to `secrets.GITHUB_TOKEN` or GitHub PAT-like secret names
  in steps that can write to GitHub, deploy, release, merge, or dispatch
  workflows;
- environment variables named like `GITHUB_TOKEN`, `GH_TOKEN`, or
  `GITHUB_PAT` in tool/action execution context.

Emits:

- file path and line if available;
- message that the agent or workflow appears to hold direct GitHub write
  credentials;
- remediation to restrict token permissions, require approval for write/deploy
  paths, and route risky operations through AgentVeil policy/proof controls
  where applicable.

Evidence policy:

- report presence and variable/key name only;
- never report token values.

### `workflow.deploy_without_approval`

Reads:

- `.github/workflows/*.yml`;
- `.github/workflows/*.yaml`.

Matches:

- deployment-like jobs or steps (`deploy`, `release`, `publish`, `kubectl`,
  `terraform apply`, cloud deploy actions, production environment names);
- absence of an explicit approval gate such as protected GitHub environments,
  reviewer-required environment usage, or a clearly named manual approval job.

Emits:

- workflow file and line for the deployment job/step where practical;
- message that deployment appears possible without an approval gate;
- remediation to add protected environments or explicit approval before
  production deploy workflows.

Evidence policy:

- report job or step label only;
- no command bodies containing secret-like values.

### `workflow.pull_request_target_secrets_risk`

Reads:

- `.github/workflows/*.yml`;
- `.github/workflows/*.yaml`.

Matches:

- `on: pull_request_target`;
- plus risky use of checkout, script execution, dependency install, or secret
  access in jobs triggered by untrusted PR context.

Emits:

- workflow file and trigger line if available;
- message that `pull_request_target` can expose secrets to untrusted changes
  when combined with checkout or execution;
- remediation to use `pull_request` for untrusted checks, avoid checking out
  fork code under `pull_request_target`, and isolate privileged jobs.

Evidence policy:

- report trigger and risky step names only.

### `tool.shell_without_approval`

Reads:

- pinned agent tool manifests identified by `Static Candidate Discovery`;
- GitHub workflow steps that grant shell execution to agent-controlled inputs.

Matches:

- shell tools enabled without an approval field, policy gate, allowlist, or
  restricted command set;
- configuration keys such as `shell`, `bash`, `command`, `terminal`, or
  `subprocess` paired with unconstrained execution flags in the pinned
  agent-manifest formats only.

Emits:

- config/workflow file and line if available;
- message that shell execution appears available without approval;
- remediation to require human approval or explicit policy gates for shell
  access, especially production-affecting commands.

Evidence policy:

- report tool name or key path only;
- no raw command content if it contains secret-like material.

### `identity.private_key_unencrypted`

Reads:

- file metadata and a bounded header prefix only;
- candidate files with key-like names or PEM-like first lines.

Matches:

- PEM private key headers such as `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`,
  `BEGIN EC PRIVATE KEY`, or `BEGIN OPENSSH PRIVATE KEY`;
- no encrypted-key marker in the bounded header prefix.

Encrypted-key markers that must not fire:

- `BEGIN ENCRYPTED PRIVATE KEY` for encrypted PKCS#8 PEM;
- `Proc-Type: 4,ENCRYPTED` for legacy encrypted PKCS#1/SEC1 PEM.

Emits:

- file path;
- line `1` when header starts at the first line;
- message that an unencrypted private key file appears present;
- remediation to remove the key from the repo, rotate it if exposed, store it
  in a secret manager, and require encrypted private key material when local
  keys are unavoidable.

Evidence policy:

- report only the header class and path;
- never report key bytes beyond generic header classification.

## JSON Report Schema

Stable v0.1 shape:

```json
{
  "report_version": "0.1",
  "scanner_version": "agentveil-posture/0.1.0",
  "scanned_at": "2026-05-06T00:00:00Z",
  "scanned_path": "/absolute/or/input/path",
  "findings": [
    {
      "rule_id": "workflow.deploy_without_approval",
      "severity": "high",
      "file": ".github/workflows/deploy.yml",
      "line": 12,
      "message": "Deployment workflow appears to run without approval.",
      "remediation": "Require protected environments or explicit approval before production deploy."
    }
  ],
  "summary": {
    "by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "total": 1
  }
}
```

Schema rules:

- `report_version` is a string and starts at `"0.1"`.
- `scanner_version` is a string in the form
  `"agentveil-posture/<package-version>"`.
- `scanned_at` is UTC ISO-8601 with `Z` and whole-second precision.
- `scanned_path` is the CLI input resolved by the scanner.
- `findings[]` is stable and redacted.
- `findings[].file` is repository-relative to `scanned_path`, using POSIX `/`
  separators.
- `line` is `null` when no line is available.
- `summary.by_severity` always includes all five severity keys.
- `summary.total` equals `len(findings)`.

## CLI Surface

Command:

```bash
agentveil posture scan --path . --output report.json
```

Arguments:

- `agentveil posture scan`: only v0.1 command. No `check` alias.
- `--path PATH`: scan root. Defaults to `.`.
- `--output FILE`: JSON output path. Required by the public v0.1 signature for
  examples and CI; Day 1 skeleton may default only for developer ergonomics if
  tests require it.

Exit codes:

- `0`: scan completed and report was written, regardless of findings for v0.1.
- `2`: invalid CLI arguments.
- `1`: scanner/reporting error.

Future flags such as `--fail-on` are deferred.

## GitHub Action Manifest Plan

Day 1 does not create `action.yml`; v0.1 will keep the action in this same repo
and distribute it as `agentveil-protocol/agentveil-posture@v0.1.0`.

Planned `action.yml` shape:

```yaml
name: AgentVeil Posture
description: Static posture scan for risky agent capabilities
inputs:
  path:
    description: Path to scan
    required: false
    default: "."
  output:
    description: JSON report output path
    required: false
    default: agentveil-posture-report.json
outputs:
  report:
    description: Path to the generated JSON report
runs:
  using: composite
  steps:
    - run: python -m pip install .
      shell: bash
    - id: scan
      run: |
        agentveil posture scan --path "${{ inputs.path }}" --output "${{ inputs.output }}"
        echo "report=${{ inputs.output }}" >> "$GITHUB_OUTPUT"
      shell: bash
```

PR/check surfacing:

- v0.1 may upload the JSON file as a workflow artifact through caller workflow
  configuration, not by scanner network calls.
- Any optional job summary must show counts and rule IDs only.
- Raw evidence, source snippets, and secret-like values must not be printed.
- Failing PRs by threshold is deferred unless explicitly approved for v0.1.

## Fixture Plan

Day 1 creates empty placeholder directories only.

`fixtures/clean_github_project/`:

- minimal repository shape;
- no GitHub deploy workflow;
- no direct GitHub token write path;
- no `pull_request_target` secret-risk pattern;
- no shell tool without approval;
- no private key file.

`fixtures/dangerous_github_project/`:

- Day 1 placeholder only;
- Day 2-4 will add one compact fixture covering all five v0.1 rules.

Full fixture matrix and false-positive reference set are deferred to v0.2.

## Test Plan

Rule unit tests:

- each rule emits the expected `rule_id`, `severity`, `file`, `line`,
  `message`, and `remediation`;
- rule IDs are unique and stable;
- every rule has remediation text;
- secret-like values are redacted.

Fixture-driven E2E:

- `clean_github_project` emits zero findings;
- `dangerous_github_project` emits exactly the five v0.1 rule IDs once fixture
  content exists;
- report summary totals match findings.

Schema validation:

- report JSON has exact v0.1 top-level keys;
- report JSON includes `scanner_version`;
- `summary.by_severity` includes all severity buckets;
- `summary.total == len(findings)`;
- `scanned_at` is UTC with `Z` and whole-second precision;
- `Finding.severity` is one of the known severity enum values;
- `Finding.rule_id` follows lowercase `category.rule_name` form;
- `Finding.file` is repo-relative, never absolute;
- `line` may be integer or null only.

Hard-constraint tests:

- monkeypatch `socket.socket` / common network entry points and assert scan does
  not call them;
- monkeypatch `urllib.request.urlopen` and `http.client.HTTPConnection` and
  assert scan does not call them;
- if `requests` or `httpx` are ever added, monkeypatch their network clients in
  the same hard-constraint suite;
- monkeypatch `subprocess.run`, `subprocess.Popen`, and `os.system` and assert
  scan does not call them;
- assert scanner source uses `yaml.safe_load` only and contains no
  `yaml.load(` calls before YAML workflow parsing is enabled;
- snapshot file hashes before and after scan and assert scanned files are not
  modified;
- assert symlinks outside the scan root are not followed by default;
- assert symlinks inside the scan root are skipped in v0.1;
- assert symlinked directories are not traversed, including directories that
  point outside the scan root;
- assert large/binary files are skipped or bounded;
- assert private-key detection reads only metadata plus a bounded header prefix;
- assert encrypted PKCS#8 PEM and legacy `Proc-Type: 4,ENCRYPTED` PEM do not
  trigger `identity.private_key_unencrypted`;
- assert scanner logs and report output do not contain raw secret fixture values.

CLI error tests:

- `--path` to a non-existent directory exits `1` without a traceback;
- `--path` to a file exits `1` without a traceback;
- `--output` to a non-creatable path exits `1` without a traceback.

Cross-platform parsing tests:

- CRLF GitHub workflow YAML parses the same as LF when workflow parsing lands.

Day 1 sanity tests:

- `pip install -e .` succeeds in a fresh virtual environment;
- `agentveil posture scan --help` prints the `posture scan` help;
- `agentveil posture scan --path . --output /tmp/report.json` exits `0`;
- `/tmp/report.json` parses as JSON and follows the empty v0.1 schema.

## Out Of Scope For v0.1 Day 1

- actual rule detection logic;
- dangerous fixture contents;
- GitHub Action manifest file;
- `check` command alias;
- `--fail-on`;
- PyPI publication;
- GitHub repository creation or remote push;
- AVP backend/core code, deployment, credentials, logs, or production changes.

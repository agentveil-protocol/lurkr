# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-07

### Added

- Added bounded Python AST agent rules for Python tool decorators,
  tool constructors, subprocess/shell calls, dynamic execution, file mutation,
  and API-key-shaped literals.
- Added static `.py` discovery using the Phase 6a bounded AST parser.
- Added redacted SARIF/JSON coverage for Python agent findings.

## [0.1.1] - 2026-05-07

### Changed

- Expanded deployment workflow markers to cover common CLI deploy and publish
  commands while preserving command-body redaction.
- Tightened deployment false-positive exclusions for build, preview, plan, and
  package-only commands.
- Detect `actions/github-script` usage under `pull_request_target` via parsed
  workflow `uses:` fields.
- Detect exact shell-capable tool names in pinned agent manifests without
  matching substrings such as `search_tool` or `shellfish`.
- Updated the README logo URL so future PyPI releases render the logo from a
  public raw GitHub URL.

## [0.1.0] - 2026-05-07

### Added

- Initial `agentveil posture scan` CLI for static, local-only AI agent posture checks.
- GitHub Action wrapper for repository posture scans.
- Pre-commit hook manifest for local posture review before commits.
- PyPI package metadata for `agentveil-posture`.
- Five high-severity v0.1 rules covering GitHub token exposure surfaces,
  deployment approval gaps, privileged pull request workflows, shell-capable
  tool manifests, and committed unencrypted private keys.
- Redacted JSON report output with rule ID, severity, file path, line number
  when available, message, and remediation.
- SARIF v2.1.0 report output for GitHub Code Scanning upload.
- Optional `--fail-on` threshold for CI and pre-commit blocking.

### Security

- Scanner is read-only, offline, telemetry-free, and static-only.
- Findings never include raw secrets, command bodies, or private key material.

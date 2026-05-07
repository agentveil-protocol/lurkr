# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-07

### Added

- Initial `agentveil posture scan` CLI for static, local-only AI agent posture checks.
- GitHub Action wrapper for repository posture scans.
- Pre-commit hook manifest for local posture review before commits.
- Five high-severity v0.1 rules covering GitHub token exposure surfaces,
  deployment approval gaps, privileged pull request workflows, shell-capable
  tool manifests, and committed unencrypted private keys.
- Redacted JSON report output with rule ID, severity, file path, line number
  when available, message, and remediation.

### Security

- Scanner is read-only, offline, telemetry-free, and static-only.
- Findings never include raw secrets, command bodies, or private key material.

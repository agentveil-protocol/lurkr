# Lurkr Agent Notes

## Project Scope

Lurkr is the posture scanner and GitHub Action for identifying risky repository and workflow patterns. Treat scanner findings, policy behavior, and action outputs as security-sensitive surfaces.

## Build and Test

```bash
python -m pip install -e ".[test]"
python -m pytest
```

Run targeted CLI or action smoke checks when changing scanner behavior, fixtures, report formats, or GitHub Action inputs/outputs.

## CI Policy

Follow [`docs/CI_POLICY.md`](docs/CI_POLICY.md).

- Run relevant local tests before pushing code changes.
- The push fast gate is not release verification.
- The full OS/Python compatibility gate and action smoke gate must pass before release tags or Docker publication.
- Do not use `[skip ci]` for code, packaging, security, or behavior changes.
- When reporting done, state the local commands and CI gates that actually ran.

## Security Discipline

- Do not commit secrets, private URLs, private customer data, or generated credentials.
- Treat workflow parsing, action behavior, and scanner output schemas as trust boundaries.
- For security-bearing changes, test both expected detections and expected non-detections.
- Keep changes narrow; do not bundle unrelated scanner, packaging, and documentation changes.

# Installed-Framework Fixtures

These fixtures validate that Lurkr recognizes canonical tool wiring
patterns while the corresponding framework packages are installed.

The validation remains static-only: `agent.py` files are parsed by Lurkr but
are not imported or executed. The runner installs each framework in an isolated
virtual environment, verifies the framework import surface is present, then runs
`lurkr scan` against the fixture directory.

Each fixture includes:

- `requirements.txt` with reproducible version bounds.
- `agent.py` with one risky pattern and one safe/control pattern.
- `expected_findings.json` with the exact expected `(rule_id, file, line)` set.

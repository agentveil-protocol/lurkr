# Contributing

Thanks for helping improve Lurkr.

## Issues

Open an issue for bugs, false positives, false negatives, documentation gaps,
or rule suggestions. Include:

- scanner version or commit SHA
- command run
- relevant file type and rule ID
- expected result
- actual result

Do not include real secrets, private keys, tokens, production logs, or customer
data. Redact examples before posting.

## Pull Requests

Keep PRs focused on one change. For rule changes, include tests that cover both
the positive detection case and at least one non-match case.

Before opening a PR, run:

```bash
python -m pip install -e '.[test]'
python -m pytest
```

Also run:

```bash
git diff --check
```

## Development Setup

```bash
git clone https://github.com/agentveil-protocol/lurkr
cd lurkr
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest
```

## Rule Guidelines

Lurkr rules should remain static, local-only, read-only, and
secret-safe. Detection logic must not execute scanned project code, call the
network, or report raw secret material.

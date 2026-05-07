# workflow.pull_request_target_secrets_risk

Flags `pull_request_target` workflows that combine privileged context with
checkout, run, secrets, or scriptable GitHub access.

## Why It Matters

`pull_request_target` runs with base-repository privileges. Mixing it with
untrusted pull request content can expose tokens or write access.

## Review

Bad:

```yaml
on: pull_request_target
steps:
  - uses: actions/checkout@v4
  - run: npm test
```

Good:

```yaml
on: pull_request
steps:
  - uses: actions/checkout@v4
  - run: npm test
```

## Framework Note

Metadata-only label workflows may be valid. Avoid checkout of PR head code and
restrict token permissions.

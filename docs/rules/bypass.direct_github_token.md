# bypass.direct_github_token

Flags direct GitHub token capability in workflows or agent manifests.

## Why It Matters

`GITHUB_TOKEN` and personal access tokens can read or write repository state.
Agent-accessible workflows or manifests should keep that capability narrow and
visible.

## Review

Bad:

```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Good:

```yaml
permissions:
  contents: read
```

## Framework Note

Expected bot workflows can still trigger this rule. Confirm token permissions,
workflow trigger, and whether write actions require approval.

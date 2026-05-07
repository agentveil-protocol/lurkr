# workflow.deploy_without_approval

Flags deploy, release, publish, or registry-push steps without an approval
signal in the same workflow.

## Why It Matters

Deployment capability changes external systems. A protected environment, manual
approval, or equivalent gate should sit before production-impacting steps.

## Review

Bad:

```yaml
- name: Deploy
  run: terraform apply
```

Good:

```yaml
environment: production
steps:
  - name: Deploy
    run: terraform apply
```

## Framework Note

Build, plan, preview, and package-only commands are excluded unless the same
step also contains a deploy marker.

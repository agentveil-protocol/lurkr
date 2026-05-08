# tool.shell_without_approval

Flags agent manifests that expose shell-capable tools without an approval flag.

## Why It Matters

Shell tools can read files, mutate the working tree, call networks, and run
deploy commands. They should be restricted or explicitly approved.

## Review

Bad:

```json
{"tools": [{"name": "shell", "shell": "bash"}]}
```

Good:

```json
{"tools": [{"name": "shell", "shell": "bash", "approval_required": true}]}
```

## Framework Note

The rule matches literal shell-capable tool names and fields in supported agent
manifest files.

# Lurkr Attack Trees

Bruce Schneier introduced attack trees as a practical way to describe how an
attacker can reach a goal through smaller sub-goals and concrete techniques.
They remain useful because they make coverage visible: a security team can look
at a goal, enumerate the ways it might be reached, and mark which leaves are
covered by controls or detection.

Lurkr uses that framing for the agent capability surface. Each
tree below starts with an attacker goal that matters before deployment. The
leaves are repository-visible techniques, and each leaf is indexed by the
Lurkr rule ID that detects it.

Reference: Bruce Schneier, "Attack Trees", Dr. Dobb's Journal, December 1999 —
https://www.schneier.com/academic/archives/1999/12/attack_trees.html

## Reading The Trees

The root line is the attacker goal. Indented children are sub-goals. `AND`
means the attacker needs the grouped conditions together. A leaf without `AND`
is a concrete technique that can contribute directly to the goal. Bracketed
items are Lurkr rule IDs; those are the scanner checks that cover the leaf.

These five trees are not complete threat models. They are coverage maps for the
v0.2.1 rule set. Leaves without a rule ID in your own threat model identify a
gap to cover with another control or a candidate future Lurkr rule.

## Tree 1: Unauthorized Production Deploy

```text
Goal: agent performs unauthorized production deploy
|
|-- AND: agent has GitHub write capability
|   |-- direct GITHUB_TOKEN reference in workflow      [bypass.direct_github_token]
|   `-- direct PAT reference in agent manifest         [bypass.direct_github_token]
|
|-- AND: deploy step runs without human gate
|   |-- deploy job missing protected environment       [workflow.deploy_without_approval]
|   `-- release/publish step without approval flag     [workflow.deploy_without_approval]
|
`-- AND: PR-triggered context has elevated trust
    `-- pull_request_target with secrets and checkout  [workflow.pull_request_target_secrets_risk]
```

This tree covers the path from repository automation to production-affecting
change. The root is not limited to application deploys; package publishing,
registry pushes, releases, infrastructure apply commands, and other promotion
paths fit the same model.

Review notes:

- `bypass.direct_github_token` covers direct token capability, not every
  possible credential source.
- `workflow.deploy_without_approval` covers missing visible approval gates in
  the workflow. External approval systems still need human verification.
- `workflow.pull_request_target_secrets_risk` covers elevated PR context when
  it combines with checkout, execution, secrets, or scriptable GitHub access.

Common gap questions:

- Does the project deploy from a system outside GitHub Actions?
- Does a cloud role or deployment token sit outside the repository surface?
- Does branch protection or environment protection exist but not appear in the
  workflow file?

If the answer to any of those is yes, Lurkr findings still help focus review,
but the tree needs complementary controls beyond this scanner.

## Tree 2: Agent Executes Arbitrary Code On Host

```text
Goal: agent executes arbitrary code on host system
|
|-- shell-capable tool declared without approval         [tool.shell_without_approval]
|
|-- Python tool calls subprocess                         [agent.python_subprocess_in_tool]
|
|-- Python tool calls eval or exec                       [agent.python_eval_exec_in_tool]
|
`-- Python tool without approval marker (broad surface)  [agent.python_tool_without_approval]
```

This tree covers the host-execution path: an agent gets access to a tool, and
that tool can cross from model-selected action into command execution or
dynamic code execution.

Review notes:

- `tool.shell_without_approval` covers pinned manifest formats and exact
  shell-capable tool names.
- `agent.python_subprocess_in_tool` covers recognized Python tool functions
  that call subprocess or shell APIs directly.
- `agent.python_eval_exec_in_tool` covers direct dynamic execution sinks inside
  recognized Python tool functions.
- `agent.python_tool_without_approval` is intentionally broad. It identifies
  tool exposure without a conservative approval marker, even when the tool body
  does not contain a known sink.

Common gap questions:

- Does the project construct tools dynamically at runtime?
- Does a tool call a helper in another file that performs execution?
- Does the agent framework expose tools from configuration that Lurkr does
  not yet parse?

Those are future coverage candidates. In v0.2.1, Lurkr keeps this tree tied to
the same-file and pinned-manifest surfaces it can inspect reliably.

## Tree 3: Credential Exfiltration

```text
Goal: attacker obtains credential from agent surface
|
|-- unencrypted private key committed to repository      [identity.private_key_unencrypted]
|
`-- API key hardcoded in Python source                   [agent.python_api_key_hardcoded]
```

This tree covers credentials that are visible in the repository at scan time.
It is deliberately narrower than a full secret-scanning model: Lurkr focuses
on credential shapes that connect directly to agent identity, API access, or
agent-controlled execution surfaces.

Review notes:

- `identity.private_key_unencrypted` is the most directly actionable leaf. A
  committed unencrypted private key should usually be removed and rotated if it
  was exposed.
- `agent.python_api_key_hardcoded` is module-wide, not limited to recognized
  tool functions, because keys are often stored in module-level constants or
  configuration blocks.

Common gap questions:

- Are there historical commits containing credentials?
- Are there provider-specific token shapes outside Lurkr's current key
  patterns?
- Are secrets loaded from CI, cloud stores, or local files during runtime?

Those questions belong in a broader credential review. Lurkr contributes by
surfacing the repository-visible agent credential leaves it currently covers.

## Tree 4: Agent Corrupts Or Deletes Data

```text
Goal: agent writes or deletes data outside intended scope
|
`-- Python tool with unrestricted file access            [agent.python_unrestricted_file_access]
```

This tree is small because v0.2.1 has one direct file-mutation rule. That narrow
scope is intentional: the scanner reports the clearest repository-visible sign
that an agent-callable Python tool can write or delete files.

Review notes:

- `agent.python_unrestricted_file_access` covers file write and delete calls
  inside recognized Python tool functions.
- The rule does not decide whether the path is acceptable. Reviewers still
  need to check whether the tool constrains writes to an intended workspace.
- A finding is higher priority when the same function also exposes shell,
  dynamic execution, or broad approval-free tool access.

Common gap questions:

- Does the tool use a helper function for file mutation?
- Does the project write through a framework-specific storage abstraction?
- Does the runtime mount sensitive host paths into the agent workspace?

Those gaps are outside v0.2.1's static same-file model. They are useful inputs
for future rule additions when real projects show repeatable patterns.

## Tree 5: Agent Gains Capability Beyond Declared Scope

```text
Goal: agent reaches capability not in declared review scope
|
`-- Python tool registered but not in agent manifest    [agent.declared_vs_imported_delta]
```

This tree covers the review-scope bypass path: a manifest appears to declare
what an agent can call, but Python code registers an additional reachable tool.

Review notes:

- `agent.declared_vs_imported_delta` compares supported manifest declarations
  with Python tool registrations after framework-independent `snake_case`
  normalization.
- The rule needs at least one supported manifest. Without a declared baseline,
  Lurkr cannot identify a declared-vs-imported delta.
- The rule reports the forward delta only: registered tools absent from
  manifests. Manifest declarations absent from code are a separate review
  question.

Common gap questions:

- Does the project build tool names dynamically at runtime?
- Does a tool registration point to a helper function in another file?
- Does the repository use a manifest format outside Lurkr's current discovery
  scope?

Those gaps are outside v0.2.1's static manifest/code comparison model. They are
useful inputs for future rule additions if real projects show repeatable
patterns.

## Using These Trees

Security teams can map existing threat model nodes to Lurkr rule IDs. If a
node in your model matches one of the leaves above, run `lurkr scan` and use
the matching finding as review evidence for that capability surface.

For gap analysis, copy the relevant tree and add your own leaves. Leaves with
Lurkr rule IDs are covered by the current scanner. Leaves without rule IDs
fall into one of two categories: an existing-rule scope gap that should be
filed as an issue, or a non-scanned surface that needs another control.

This structure is also roadmap signal. When multiple users report the same
uncovered leaf, it becomes a strong candidate for a future rule because it has
evidence, a threat-model location, and a clear relation to the capability
surface Lurkr already scans.

## Coverage Boundary

The trees deliberately describe pre-deployment repository surfaces. They do not
model prompt injection at runtime, user authorization flows, cloud IAM policy
evaluation, network egress controls, or runtime mediation. Those controls may
be necessary for the full system, but they sit outside the static local scanner
boundary.

The value of these trees is focus. A reviewer can ask a narrow question:
"Which repository-visible leaves make this agent capable of deployment,
execution, credential exposure, or data mutation before it ships?" Lurkr
answers that question with rule IDs, redacted findings, and stable remediation
text.

## Citation

Bruce Schneier, "Attack Trees", Dr. Dobb's Journal, December 1999 —
https://www.schneier.com/academic/archives/1999/12/attack_trees.html

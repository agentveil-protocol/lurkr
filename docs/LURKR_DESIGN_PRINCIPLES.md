> "You can't trust code that you did not totally create yourself."
> — Ken Thompson, *Reflections on Trusting Trust*, ACM Turing Award Lecture, Communications of the ACM 27(8), August 1984

# Lurkr Design Principles

Lurkr rules are not arbitrary heuristics. They are detection points
for violations of protection principles that have been load-bearing in secure
systems design for decades.

This document maps each shipped v0.2.1 rule to the foundational principle or
principles it enforces. The mapping is intentionally concrete: every rule
identifies a repository surface where an agent, tool, workflow, or credential
can bypass the protection boundary a reviewer expects to exist.

Lurkr is the pre-deployment scanner workstream in the broader AgentVeil
ecosystem. Its job is to find risky capability surfaces before deployment, not
to approve, block, or prove runtime actions. That boundary is part of the
design: each rule points at a place where a downstream decision or proof system
would need reliable information about what the agent can touch.

## The Saltzer-Schroeder Principles

Jerome H. Saltzer and Michael D. Schroeder's 1975 paper, "The Protection of
Information in Computer Systems", remains one of the clearest statements of
how secure systems should be designed:
https://www.cs.virginia.edu/~evans/cs551/saltzer/

- **Economy of mechanism** — keep the design as simple and small as possible.
- **Fail-safe defaults** — base access decisions on permission rather than
  exclusion.
- **Complete mediation** — every access to every object must be checked for
  authority.
- **Open design** — the design should not depend on the ignorance of
  attackers.
- **Separation of privilege** — a protection mechanism that requires two keys
  to unlock is more robust than one that requires only a single key.
- **Least privilege** — every program and every privileged user should operate
  using the least amount of privilege necessary.
- **Least common mechanism** — minimize mechanisms common to more than one
  user and depended on by all users.
- **Psychological acceptability** — the human interface must be designed for
  ease of use.

Not every shipped rule maps to every principle. The v0.2.1 rule set focuses on
the principles most directly violated by repository-visible agent capability
surfaces: fail-safe defaults, complete mediation, least privilege, separation
of privilege, economy of mechanism, and least common mechanism. Open design
and psychological acceptability remain important design constraints for the
product itself, but they are not the primary finding category for the current
ten rules.

## Mapping Discipline

This mapping is intentionally conservative. A rule only cites a principle when
the repository pattern gives a direct, reviewable reason to believe that
principle is under pressure.

The mapping does not claim that a single finding proves exploitation. It says
the repository contains a capability surface that weakens a known protection
principle and deserves review before deployment.

The mapping also does not claim that absence of a finding proves the principle
is fully satisfied. Static analysis has documented limits; the principle map is
a way to explain the rules Lurkr does ship, not a certificate that every
possible rule has been implemented.

## Principle Coverage Summary

| Principle | v0.2.1 rules that primarily exercise it |
|---|---|
| Fail-safe defaults | `bypass.direct_github_token`, `workflow.deploy_without_approval`, `identity.private_key_unencrypted`, `agent.python_api_key_hardcoded` |
| Complete mediation | `workflow.pull_request_target_secrets_risk`, `tool.shell_without_approval`, `agent.python_tool_without_approval`, `agent.declared_vs_imported_delta` |
| Least privilege | `workflow.pull_request_target_secrets_risk`, `tool.shell_without_approval`, `agent.python_subprocess_in_tool`, `agent.python_eval_exec_in_tool`, `agent.python_unrestricted_file_access` |
| Separation of privilege | `workflow.deploy_without_approval`, `agent.python_tool_without_approval`, `agent.python_subprocess_in_tool` |
| Economy of mechanism | `identity.private_key_unencrypted`, `agent.python_eval_exec_in_tool`, `agent.python_api_key_hardcoded` |
| Least common mechanism | `bypass.direct_github_token` |
| Open design | `agent.declared_vs_imported_delta` |

The detailed sections below are the authoritative mapping for v0.2.1. The summary
is only an index for reviewers who want to start from a principle and then
drill down into the rule IDs.

## Rule-To-Principle Mapping

### bypass.direct_github_token

**Principles enforced:** Least Common Mechanism, Fail-Safe Defaults

**What the rule detects:** Flags direct GitHub token capability in workflows or
agent manifests.

**Why these principles:** A broad GitHub token becomes a common mechanism when
many workflow steps, tools, or agents can depend on it. That makes the token a
shared bypass path rather than a narrow authority boundary. The safe default is
to avoid exposing direct write credentials unless a workflow or tool has a
clear permission reason to hold them.

### workflow.deploy_without_approval

**Principles enforced:** Fail-Safe Defaults, Separation of Privilege

**What the rule detects:** Flags deploy, release, publish, or registry-push
steps without an approval signal in the same workflow.

**Why these principles:** Production-affecting workflows should default to no
deployment until an explicit approval path exists. The approval gate acts as a
second key: the workflow may know how to deploy, but it should not be able to
promote or publish without a separate human or protected-environment decision.

### workflow.pull_request_target_secrets_risk

**Principles enforced:** Complete Mediation, Least Privilege

**What the rule detects:** Flags `pull_request_target` workflows that combine
privileged context with checkout, run, secrets, or scriptable GitHub access.

**Why these principles:** `pull_request_target` gives a workflow elevated base
repository context while handling untrusted pull request input. Complete
mediation breaks when untrusted code can reach privileged checkout, execution,
or secrets paths without a clear authority check. Least privilege requires
privileged PR automation to stay narrowly scoped to metadata operations unless
it has a deliberate isolation design.

### tool.shell_without_approval

**Principles enforced:** Complete Mediation, Least Privilege

**What the rule detects:** Flags agent manifests that expose shell-capable
tools without an approval flag.

**Why these principles:** Shell access is a direct mediation point between an
agent and the host system. If a manifest exposes shell, bash, command,
terminal, or subprocess capability without approval, the access path is not
being checked at the point of use. Least privilege requires shell capability to
be absent, narrowed, or explicitly gated.

### identity.private_key_unencrypted

**Principles enforced:** Fail-Safe Defaults, Economy of Mechanism

**What the rule detects:** Flags committed PEM private key files that appear to
be unencrypted.

**Why these principles:** A committed unencrypted private key reverses the
default: possession of the repository becomes enough to use the identity. That
is not a permission-based default. It also complicates the system by spreading
identity material across source control instead of keeping key handling in a
small, dedicated secret-management mechanism.

### agent.python_tool_without_approval

**Principles enforced:** Complete Mediation, Separation of Privilege

**What the rule detects:** Flags supported Python tool declarations without a
conservative approval marker.

**Why these principles:** A Python function exposed as an agent tool becomes an
authority boundary. Complete mediation requires that boundary to be visible and
checked rather than implicitly trusted because the function is callable.
Separation of privilege requires risky tool use to depend on a second decision
path, such as human approval or a policy gate, instead of model selection
alone.

### agent.python_subprocess_in_tool

**Principles enforced:** Least Privilege, Separation of Privilege

**What the rule detects:** Flags subprocess or shell calls inside supported
Python tool functions.

**Why these principles:** Subprocess access gives a tool authority beyond
ordinary data transformation. Least privilege requires that authority to be
removed or narrowed unless it is essential. Separation of privilege requires an
additional approval or allowlist before an agent-callable function can cross
from Python tool logic into host command execution.

### agent.python_eval_exec_in_tool

**Principles enforced:** Least Privilege, Economy of Mechanism

**What the rule detects:** Flags `eval`, `exec`, `compile`, or dynamic import
calls inside supported Python tool functions.

**Why these principles:** Dynamic execution gives a tool the privilege to turn
data into code. That is broader authority than most agent tools need. It also
expands the trusted mechanism from a reviewable function body into an
open-ended interpreter path, making the mechanism harder to reason about and
harder to keep small.

### agent.python_unrestricted_file_access

**Principles enforced:** Least Privilege

**What the rule detects:** Flags file write or delete calls inside supported
Python tool functions.

**Why these principles:** File mutation is a persistent side effect. An
agent-callable tool should not be able to write or delete arbitrary files when
its task only requires reading, summarizing, or operating inside a bounded
workspace. Least privilege requires file access to be constrained to the
minimal paths and operations needed for the tool's purpose.

### agent.python_api_key_hardcoded

**Principles enforced:** Fail-Safe Defaults, Economy of Mechanism

**What the rule detects:** Flags API-key-shaped Python string literals.

**Why these principles:** A hardcoded API key makes source possession enough to
attempt API access, which is the opposite of a fail-safe permission default. It
also spreads credential handling into application code instead of keeping it in
the smallest practical secret-management mechanism. Removing the literal keeps
the code path simpler and the credential boundary clearer.

### agent.declared_vs_imported_delta

**Principles enforced:** Open Design, Complete Mediation

**What the rule detects:** Python tool registrations whose names are absent
from declared agent manifests (MCP/CrewAI/AutoGen/LangChain).

**Why these principles:** Open Design requires that system protection not
depend on attacker ignorance: a manifest's declared tool list is the open,
reviewable scope of the agent. Shadow capabilities hide reachable behavior from
that scope, violating open design. Complete Mediation requires every access to
be checked at a known authority point: when a tool registration bypasses the
manifest review checkpoint, the mediation chain breaks.

## Closing Note

This mapping is a maintained contract. Rules added in future versions will
explicitly cite the protection principle or principles they enforce in their
`docs/rules/*.md` page, so reviewers can connect each finding back to a stable
security-design rationale.

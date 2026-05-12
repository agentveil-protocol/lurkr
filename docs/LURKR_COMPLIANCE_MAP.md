# Lurkr Compliance Map

Lurkr findings map cleanly to several AI-specific security and
risk frameworks that teams already use when reviewing agent systems. This
document gives reviewers a compact cross-walk from framework entries to
Lurkr rule IDs.

The map is evidence-oriented. A Lurkr scan does not create compliance by
itself, and a clean scan does not prove that a system satisfies a framework.
It provides pre-deployment evidence about repository-visible agent capability
risks that can be attached to broader review, audit, and risk-management
artifacts.

## How To Read This Map

Each table maps a framework entry to the Lurkr rule IDs that produce relevant
findings. A rule ID means the scanner can surface at least one concrete
repository pattern associated with that framework concern.

Rules listed under a framework entry do not cover the entire entry. For
example, `agent.python_api_key_hardcoded` contributes evidence for sensitive
information disclosure because it detects API-key-shaped Python string
literals, but it does not cover every possible secret source, every runtime
leak, or historical commits.

Entries marked as "not currently covered" are intentional gaps. They are
documented so reviewers can plan complementary controls and so repeated
customer demand can guide future rule additions.

## OWASP Top 10 For Large Language Model Applications

The OWASP Top 10 for Large Language Model Applications v2, released in 2025,
is a widely recognized list of LLM-specific application risks:
https://owasp.org/www-project-top-10-for-large-language-model-applications/

Lurkr maps most directly to entries where repository-visible agent
capability, credentials, tool invocation, or host-side side effects create
pre-deployment risk.

| OWASP LLM entry | Lurkr rules covering |
|---|---|
| LLM01:2025 Prompt Injection | `agent.dynamic_prompt_from_user_input` |
| LLM02:2025 Sensitive Information Disclosure | `agent.python_api_key_hardcoded`, `identity.private_key_unencrypted`, `agent.credential_to_llm_context` |
| LLM03:2025 Supply Chain | `agent.unverified_mcp_endpoint` |
| LLM06:2025 Excessive Agency | `agent.python_tool_without_approval`, `agent.declared_vs_imported_delta`, `agent.python_subprocess_in_tool`, `agent.python_eval_exec_in_tool`, `agent.python_unrestricted_file_access`, `tool.shell_without_approval` |
| LLM07:2025 System Prompt Leakage | (not currently covered — gap noted) |
| LLM08:2025 Vector and Embedding Weaknesses | (not currently covered — gap noted) |
| LLM05:2025 Improper Output Handling | (not currently covered — gap noted) |

### OWASP Coverage Notes

`agent.python_api_key_hardcoded`, `identity.private_key_unencrypted`, and
`agent.credential_to_llm_context` support LLM02 review by finding credential
material that can be exposed through the repository or model context before an
agent ships. These rules are intentionally redacted: they report paths and rule
IDs, not raw key values.

The LLM06 mapping is the strongest OWASP alignment for v0.2.2. Lurkr's Python
tool, manifest, subprocess, dynamic execution, and file-mutation rules all
look for places where an agent has more authority than a reviewer may expect.
Those are excessive-agency indicators, not runtime proof of misuse.

`agent.dynamic_prompt_from_user_input` gives partial LLM01 coverage by
detecting a static setup pattern: direct interpolation of function parameters
into prompt-shaped strings. It does not decide whether a runtime prompt is
malicious.

`agent.unverified_mcp_endpoint` contributes to LLM03 review by surfacing
external MCP server dependencies before deployment. It does not verify a
server's provenance or tool schema; it marks the dependency as a trust review
checkpoint.

Lurkr does not currently cover LLM05, LLM07, or LLM08 directly. Improper output
handling, system prompt leakage, and vector or embedding weaknesses may be
addressed in future static rules if repeatable repository-visible patterns
emerge. Until then, teams should cover those entries with complementary design
review, live safeguards, and application-specific tests.

## MITRE ATLAS

MITRE ATLAS is an AI-specific adversary tactics and techniques knowledge base
modeled after MITRE ATT&CK:
https://atlas.mitre.org/

The technique IDs below were cross-checked against the current ATLAS data
published by MITRE at the time of writing. Lurkr maps most directly to ATLAS
tactics involving credentials, tool invocation, command execution, privilege
expansion, unauthorized deployment, and file or data impact.

| ATLAS tactic | Relevant technique area | Lurkr rules covering |
|---|---|---|
| Initial Access | AML.T0012 Valid Accounts / token misuse; untrusted external service | `bypass.direct_github_token`, `identity.private_key_unencrypted`, `agent.python_api_key_hardcoded`, `agent.unverified_mcp_endpoint` |
| Credential Access | Credential exposure through model context | `agent.credential_to_llm_context` |
| Defense Evasion | Prompt injection bypasses model alignment or instruction boundaries | `agent.dynamic_prompt_from_user_input` |
| Execution | AML.T0053 AI Agent Tool Invocation; AML.T0050 Command and Scripting Interpreter | `agent.python_subprocess_in_tool`, `agent.python_eval_exec_in_tool`, `tool.shell_without_approval` |
| Privilege Escalation | AML.T0053 AI Agent Tool Invocation; AML.T0105 Escape to Host | `agent.python_tool_without_approval`, `agent.declared_vs_imported_delta`, `tool.shell_without_approval`, `agent.python_subprocess_in_tool` |
| Impact | AML.T0081 Modify AI Agent Configuration; AML.T0101 Data Destruction via AI Agent Tool Invocation | `workflow.deploy_without_approval`, `workflow.pull_request_target_secrets_risk`, `agent.python_unrestricted_file_access` |

### ATLAS Coverage Notes

`bypass.direct_github_token` contributes to Initial Access review because a
workflow or manifest that exposes a direct GitHub token gives an adversary a
credential path into repository operations. The rule does not prove the token
was compromised; it identifies a capability that should be scoped, gated, or
removed.

`identity.private_key_unencrypted` and `agent.python_api_key_hardcoded` also
support Initial Access review. They surface repository-visible credentials
that can become valid-account or token-abuse material if copied, leaked, or
made accessible through an agent workflow.

`agent.unverified_mcp_endpoint` contributes to Initial Access review when a
repository connects an agent to an untrusted external MCP service. The finding
does not prove compromise; it identifies a remote service boundary that should
be reviewed before the agent can rely on it.

`agent.credential_to_llm_context` maps to Credential Access because credentials
placed in model-visible messages can be exposed through provider logs,
conversation history, traces, or other retained context.

`agent.dynamic_prompt_from_user_input` maps to Defense Evasion because direct
prompt interpolation can let user-controlled text bypass the intended
templating boundary and weaken alignment or instruction controls.

`agent.python_subprocess_in_tool` and `agent.python_eval_exec_in_tool` map to
Execution because they identify Python tool functions that can cross into host
command execution or dynamic code execution. `tool.shell_without_approval`
maps to the same tactic for manifest-declared shell capability.

`agent.python_tool_without_approval` and `tool.shell_without_approval` map to
Privilege Escalation when an agent can invoke a capability that the user could
not otherwise access directly. These findings indicate that authority is
available to the agent surface without a visible approval marker.

`agent.declared_vs_imported_delta` maps to the same tactic when a reachable
Python tool bypasses the declared manifest scope that reviewers use as an
authority checkpoint.

`agent.python_unrestricted_file_access` maps to Impact when an agent-callable
tool can write or delete files. `workflow.deploy_without_approval` and
`workflow.pull_request_target_secrets_risk` map to Impact because deployment,
release, publish, or privileged PR automation can alter production code,
packages, infrastructure, or data paths.

ATLAS evolves. This coverage map should be refreshed against each major ATLAS
release, especially when technique names or IDs change or when ATLAS adds new
agent-specific tactics.

## NIST AI Risk Management Framework

The NIST AI Risk Management Framework, AI 100-1 v1.0, published in January
2023, is a general-purpose AI risk framework organized around four functions:
GOVERN, MAP, MEASURE, and MANAGE:
https://www.nist.gov/itl/ai-risk-management-framework

Lurkr contributes most directly to the MEASURE function. It gives teams
repeatable pre-deployment evidence about whether agent repositories contain
risky capabilities, credential exposure, or bypass paths that should be
reviewed before release.

| NIST AI RMF subcategory | How Lurkr contributes |
|---|---|
| MEASURE 2.6 (AI system evaluated against established standards) | Lurkr scan produces evidence grounded in established protection principles (see `LURKR_DESIGN_PRINCIPLES.md`). Declared-vs-imported delta detection adds evidence of evaluation against established standards by surfacing scope deviations from the agent's declared manifest. |
| MEASURE 2.7 (information security is adequate) | Lurkr finds credential exposure, prompt-construction risks, external-service trust boundaries, and bypass paths before deployment |
| MEASURE 2.9 (AI system evaluated regularly) | Lurkr can be scheduled in CI for continuous evidence |

### NIST AI RMF Coverage Notes

For MEASURE 2.6, Lurkr provides a rule set with a documented design basis.
The scanner's findings are connected to established protection principles in
`LURKR_DESIGN_PRINCIPLES.md`, and individual rules have remediation docs in
`docs/rules/`.

For MEASURE 2.7, Lurkr contributes evidence about information security
surfaces that appear before deployment: direct GitHub token references,
unencrypted private keys, hardcoded API-key-shaped literals, privileged PR
workflows, credential flow into LLM context, prompt templates built directly
from function parameters, external MCP endpoints, and tool surfaces that can
execute commands or mutate files.

For MEASURE 2.9, Lurkr can run locally, in pre-commit, or in CI. That makes
it suitable for recurring measurement without sending repository contents to an
external service. Teams can store JSON or SARIF reports as evidence according
to their own retention process.

Lurkr is one input to MEASURE. Full AI RMF adoption requires governance,
system context, stakeholder accountability, risk acceptance, monitoring, and
response processes beyond scanner output.

## Evidence Use

The most useful way to attach Lurkr output to a framework artifact is to keep
the scanner evidence narrow and reproducible:

- Record the scanner version.
- Record the repository path or commit scanned.
- Store the JSON or SARIF report generated by the scan.
- Link each finding back to its rule documentation under `docs/rules/`.
- Link framework coverage back to this map and to
  `LURKR_DESIGN_PRINCIPLES.md`.

For a review packet, the report should answer three questions:

1. Which repository-visible agent capability surfaces were found?
2. Which framework entries do those findings support?
3. Which framework entries remain outside Lurkr coverage?

That last question is important. Gaps should remain visible so the scanner does
not become a substitute for threat modeling, runtime review, or operational
controls.

## Reporting Language

Use precise language when referencing this map:

- Prefer "Lurkr contributes evidence for MEASURE 2.7" over "Lurkr proves
  MEASURE 2.7".
- Prefer "this finding maps to LLM06" over "this system satisfies LLM06".
- Prefer "ATLAS-relevant capability surface" over "confirmed ATLAS attack".
- Prefer "not currently covered" over implying that the framework entry is
  irrelevant.

The distinction keeps the scanner useful and defensible. Lurkr reports
static, pre-deployment findings; framework adoption still depends on system
context and reviewer judgment.

## Rule Coverage Index

The following index helps reviewers move from a Lurkr finding back to the
framework entries above.

### bypass.direct_github_token

- OWASP: supports LLM06 when direct token access gives the agent excessive
  agency over repository or deployment actions.
- ATLAS: supports Initial Access review through token misuse and valid-account
  style access.
- NIST AI RMF: supports MEASURE 2.7 by identifying a bypass path before
  deployment.

### workflow.deploy_without_approval

- OWASP: supports LLM06 when deployment authority is available without a human
  or protected-environment gate.
- ATLAS: supports Impact review because deploy, release, publish, or
  registry-push steps can alter production-facing artifacts.
- NIST AI RMF: supports MEASURE 2.7 and MEASURE 2.9 when run as recurring CI
  evidence.

### workflow.pull_request_target_secrets_risk

- OWASP: supports LLM06 when privileged PR automation exposes authority to
  untrusted contexts.
- ATLAS: supports Impact review because privileged PR workflows can alter code,
  workflows, packages, or release paths.
- NIST AI RMF: supports MEASURE 2.7 by identifying a pre-deployment bypass
  path in repository automation.

### tool.shell_without_approval

- OWASP: supports LLM06 by identifying shell-capable agent tools without an
  approval flag.
- ATLAS: supports Execution and Privilege Escalation review through AI Agent
  Tool Invocation and command execution.
- NIST AI RMF: supports MEASURE 2.7 by surfacing high-risk tool capability
  before deployment.

### identity.private_key_unencrypted

- OWASP: supports LLM02 by identifying repository-visible private key material.
- ATLAS: supports Initial Access review through valid-account or key-material
  misuse.
- NIST AI RMF: supports MEASURE 2.7 by identifying credential exposure before
  deployment.

### agent.python_tool_without_approval

- OWASP: supports LLM06 by identifying Python tool declarations without a
  conservative approval marker.
- ATLAS: supports Privilege Escalation review because an agent can invoke
  capabilities that may exceed the user's direct authority.
- NIST AI RMF: supports MEASURE 2.6 and MEASURE 2.7 by creating review evidence
  tied to a documented protection-principle map.

### agent.declared_vs_imported_delta

- OWASP: supports LLM06 by identifying reachable Python tools that exceed the
  declared agent manifest scope.
- ATLAS: supports Privilege Escalation review because a shadow capability can
  expand agent authority beyond the reviewable manifest boundary.
- NIST AI RMF: supports MEASURE 2.6 by creating evidence that declared scope
  and reachable implementation were evaluated against a documented standard.

### agent.credential_to_llm_context

- OWASP: supports LLM02 by identifying credential-bearing values passed into
  LLM completion context.
- ATLAS: supports Credential Access review because credentials in model
  messages can leak through retained provider or application context.
- NIST AI RMF: supports MEASURE 2.7 by surfacing credential-to-context leak
  paths before deployment.

### agent.dynamic_prompt_from_user_input

- OWASP: supports LLM01 by identifying a static prompt-injection setup pattern:
  direct interpolation of function parameters into prompt-shaped strings.
- ATLAS: supports Defense Evasion review because direct interpolation can
  bypass the intended prompt templating boundary.
- NIST AI RMF: supports MEASURE 2.7 by surfacing prompt-construction risks
  before deployment.

### agent.unverified_mcp_endpoint

- OWASP: supports LLM03 by identifying external MCP server dependencies that
  need supply-chain and trust review.
- ATLAS: supports Initial Access review because an untrusted external service
  can become a path into the agent's tool and context surface.
- NIST AI RMF: supports MEASURE 2.7 by surfacing external-service trust
  boundaries before deployment.

### agent.python_subprocess_in_tool

- OWASP: supports LLM06 by identifying host command capability inside
  agent-callable Python tools.
- ATLAS: supports Execution and Privilege Escalation review through command
  execution and AI Agent Tool Invocation.
- NIST AI RMF: supports MEASURE 2.7 by surfacing command-execution capability
  before deployment.

### agent.python_eval_exec_in_tool

- OWASP: supports LLM06 by identifying dynamic code execution inside
  agent-callable Python tools.
- ATLAS: supports Execution review through code execution and command or
  scripting interpreter technique areas.
- NIST AI RMF: supports MEASURE 2.7 by identifying a high-risk execution sink
  before deployment.

### agent.python_unrestricted_file_access

- OWASP: supports LLM06 by identifying file write or delete capability inside
  agent-callable Python tools.
- ATLAS: supports Impact review through data destruction or unauthorized
  modification paths.
- NIST AI RMF: supports MEASURE 2.7 by surfacing persistent side-effect
  capability before deployment.

### agent.python_api_key_hardcoded

- OWASP: supports LLM02 by identifying API-key-shaped Python string literals.
- ATLAS: supports Initial Access review through token misuse and credential
  exposure.
- NIST AI RMF: supports MEASURE 2.7 by identifying credential exposure before
  deployment.

## Known Gaps

This map documents gaps rather than hiding them. Lurkr v0.2.2 does not cover
runtime prompt injection, system prompt leakage, vector-store poisoning,
embedding weakness, output handling, model behavior evaluation, authorization
logic, cloud IAM policy evaluation, runtime network egress, or historical
secret exposure.

Those areas need complementary controls. Some may become Lurkr rules if
there is a repeatable static pattern that can be detected with high confidence
from repository files. Others belong to runtime mediation, application tests,
architecture review, or operational monitoring.

## Closing Note

Use this map by pointing auditors, security reviewers, and AI safety leads to
the rule IDs that cover each framework entry. The mapping is intentionally
honest about gaps, so teams can combine Lurkr findings with the right
complementary controls instead of treating a scanner report as a complete
framework answer.

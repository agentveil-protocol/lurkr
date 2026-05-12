# agent.credential_to_llm_context

Detects credential-bearing values passed into LLM completion context. This
surfaces credentials that can leak through chat messages, provider logs, or
conversation history.

## What It Flags

This rule looks for credential variables and literals that flow into supported
LLM completion calls. It reports when a credential-like value is used in a chat
message body, `content` field, `system` field, prompt argument, or positional
argument to a recognized model call.

Credential sources include:

- Variables assigned from `os.getenv(...)`, `os.environ.get(...)`, or
  `os.environ[...]` where the environment variable name contains token, key,
  secret, password, bearer, auth, or API-key terms.
- Variables whose own names contain credential terms such as `api_key`,
  `token`, `secret`, `password`, `bearer`, or `auth_header`.
- API-key-shaped string literals assigned to variables that are then passed to
  LLM calls.

Supported LLM call patterns include direct OpenAI, Anthropic, Gemini, and
common LangChain `.invoke(...)` call sites. The rule is static and local-only:
it does not call providers or execute project code.

## Why It Matters

Credentials belong in client configuration, headers, or secret-management
paths. They should not become part of the text context sent to a model. Once a
credential is placed in a chat message or prompt, it may be stored in
conversation history, logs, traces, or other provider-side systems outside the
intended credential boundary.

This rule catches the leak path before deployment. It is not a generic secret
scanner: it reports the specific moment where credential material enters LLM
context.

## Triggers

Bad:

```python
import os
from openai import OpenAI


def summarize(repo):
    token = os.getenv("GITHUB_TOKEN")
    client = OpenAI()
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": f"Summarize {repo} using token {token}"}
        ],
    )
```

The token is loaded from the environment and interpolated into a message body.
Lurkr reports the LLM call.

Good:

```python
import os
from openai import OpenAI


def summarize(repo):
    api_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=api_key)
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": f"Summarize {repo}"}],
    )
```

The credential configures the provider client and does not appear in the
message body, so this rule does not fire.

## Known Limitations

- Credential detection is heuristic. It uses variable names, environment
  variable names, simple assignment flow, and known API-key-shaped literals.
- Cross-file flow is out of scope for v0.2.2.
- Credentials passed through containers or helper objects may not be detected
  unless the value is visible in the same file.
- The rule does not report credentials used in HTTP headers, logging, or
  printing. It is scoped to credential flow into LLM context.
- Pipeline-style LangChain composition such as `prompt | model | parser` is
  not fully resolved in v0.2.2.

## Remediation

Pass credentials only through provider client configuration, headers, or a
secret-management layer. Do not include credentials in chat messages, prompt
templates, tool arguments, examples, or system instructions. If a credential
has already been sent to a provider as context, rotate it according to the
provider and project incident-response process.

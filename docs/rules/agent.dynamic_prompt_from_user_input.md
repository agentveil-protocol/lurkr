# agent.dynamic_prompt_from_user_input

Detects prompt templates built by directly interpolating function parameters.
This surfaces statically visible prompt-injection setup before the prompt is
sent to a model.

## What It Flags

This rule looks for prompt-shaped strings constructed with direct function
parameter interpolation. It reports prompt variables, prompt-template helper
calls, and `prompt=` arguments when the template body is built with:

- f-string interpolation, such as `f"Answer this: {user_input}"`
- string concatenation, such as `"Answer this: " + user_input`
- `.format(...)` interpolation with a function parameter
- percent formatting with a function parameter

Prompt-shaped targets include names such as `prompt`, `prompt_template`,
`system_prompt`, `user_message`, `instruction`, `template`, and `query`, plus
common LangChain prompt-template constructors.

## Why It Matters

Prompt templates are a mediation boundary. Reviewers can inspect the fixed
instruction text and the placeholders where user input is expected. Direct
interpolation bypasses that boundary by mixing untrusted function parameters
into the prompt body before the templating layer can treat the input as data.

This rule does not claim the prompt is exploited. It identifies a repository
pattern that makes prompt injection easier to introduce and harder to review.

## Triggers

Bad:

```python
def answer(user_input):
    prompt = f"You are an admin assistant. Follow this request: {user_input}"
    return model.invoke(prompt)
```

The function parameter is directly interpolated into the prompt body. Lurkr
reports the prompt construction.

Good:

```python
from langchain_core.prompts import ChatPromptTemplate


def answer(user_input):
    prompt = ChatPromptTemplate.from_template(
        "You are an admin assistant. Follow this request: {request}"
    )
    return (prompt | model).invoke({"request": user_input})
```

The template is fixed and the user value is passed through an explicit
placeholder input dict, so this rule does not fire.

## Known Limitations

- The rule uses same-file static analysis and simple parameter alias tracking.
  Cross-file flow is out of scope for v0.2.2.
- Known-safe wrapper functions are not modeled in v0.2.2. If a project wraps
  prompt construction in a sanitizer, review the finding in context.
- The rule only reports prompt-shaped targets. A non-prompt f-string in a log
  or error message is intentionally ignored.
- Pipeline-style framework composition is only detected when the unsafe
  interpolation is visible at the prompt construction site.

## Remediation

Use a prompt template with explicit placeholders and pass user input as data
through the framework's input dictionary or equivalent API. Keep the
instruction text fixed and reviewable. If direct interpolation is unavoidable,
constrain and normalize the parameter before construction and document the
reason in code review.

# Hermes + Lurkr: MCP capability visibility before you enable a server

A short, local-only workflow for inspecting what an MCP server can do before
you turn it on inside [Hermes](https://github.com/NousResearch/hermes-agent),
then mapping the result into Hermes' own `tools.include` / `tools.exclude`,
`resources`, and `prompts` filters.

## Who this is for

Hermes users who are adding a new MCP server to their config and want a
practical pre-enable review step. You already know that Hermes supports MCP
and per-server tool filtering. This guide adds one extra step: scan locally
before the model gets to see the server's tools.

## Why pre-enable visibility matters

An MCP server can register many tools at once. Some only read data; others can
write files, call external services, run shell commands, mutate cloud
resources, or send messages on your behalf. The set of tools a server actually
registers is not always obvious from the server's name or README.

Hermes lets you constrain that surface with `tools.include`, `tools.exclude`,
`resources`, and `prompts`. The missing step in most workflows is simply
*looking* at what the server exposes — and at any matching capability
patterns inside the server's source — before you decide which tools to expose
to the model.

Lurkr fills that pre-enable visibility step. It is a static, local-only
scanner; it does not change Hermes behavior or sit in the runtime path.

## Step 1 — Run Lurkr locally

Install and run against the MCP server's source directory (or a clone of its
repo):

```bash
pip install lurkr
lurkr scan --path /path/to/mcp-server --output lurkr-report.json
```

For review-only output, omit `--fail-on`. To turn the scan into a CI gate on
high-severity findings:

```bash
lurkr scan --path /path/to/mcp-server --output lurkr-report.json --fail-on high
```

The scan is read-only: it does not execute the project, does not make network
calls, and writes output only to the path you provide. See the Lurkr
[Privacy & Data Handling](../../README.md#privacy--data-handling) section for
the full list of guarantees.

## Step 2 — Read the report

Each finding contains a `rule_id`, `severity`, repository-relative `file`,
optional `line`, redacted `message`, and a `remediation` pointer. A relevant
example for MCP triage looks like this:

```json
{
  "scanner_version": "lurkr/0.3.0",
  "report_version": "0.1",
  "findings": [
    {
      "rule_id": "agent.unverified_mcp_endpoint",
      "severity": "high",
      "file": ".mcp.json",
      "line": 4,
      "message": "MCP server endpoint points to an external host; review the server trust posture before deployment."
    }
  ]
}
```

The full list of rules is in the Lurkr [Detection scope](../../README.md#detection-scope)
table. The ones most relevant to MCP review are:

- `agent.unverified_mcp_endpoint` — MCP server URLs pointing to
  non-allowlisted external hosts.
- `agent.declared_vs_imported_delta` — tool registrations not declared in
  the agent manifest (covers MCP manifests and bounded TS/JS `registerTool`
  shapes).
- `tool.shell_without_approval` — manifest entries that enable shell
  execution without an approval flag.
- `agent.javascript_child_process_in_tool`,
  `agent.javascript_file_mutation_in_tool`,
  `agent.javascript_env_secret_access_in_tool`,
  `agent.javascript_network_call_in_tool` — Node.js capabilities reached
  from canonical MCP `registerTool` handlers (TS/JS, bounded scope).

Treat these as *capability surfaces to review*, not incidents. The point is
to know what the server can do before you let Hermes call it.

## Step 3 — Map findings to Hermes MCP filters

Hermes lets each server be filtered with these keys under `tools:`
([Hermes MCP guide](https://hermes-agent.nousresearch.com/docs/guides/use-mcp-with-hermes/),
[MCP config reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference/)):

| Hermes key | Purpose |
|---|---|
| `tools.include` | Allowlist: only the listed tool names are exposed. |
| `tools.exclude` | Denylist: the listed tool names are hidden. |
| `tools.resources` | Boolean-like switch for the server's MCP resource utilities. |
| `tools.prompts` | Boolean-like switch for the server's MCP prompt utilities. |

Per the Hermes MCP config reference, if both `include` and `exclude` are set,
`include` wins. The Hermes reference also documents that server-native MCP
tools are exposed to the model with the prefix
`mcp_<server>_<tool>` (e.g. `mcp_github_create_issue`); however, use the
*original* MCP tool names inside `include` / `exclude` lists.

Suggested mapping:

- **Findings touching external hosts, write capability, secrets, shell, or
  network calls inside tool handlers** — start with a small `tools.include`
  list naming only the read or low-impact tools you actually need.
- **Findings on a server you mostly trust, with a handful of clearly mutating
  tools** — keep the broad surface and add those names to `tools.exclude`.
- **No need for the server's MCP prompts or resources** — set
  `tools.resources: false` and `tools.prompts: false`.

After changing config, reload Hermes' MCP servers with `/reload-mcp` and ask
Hermes which MCP-backed tools are available so you can confirm the surface is
what you expect.

## Example Hermes config — before and after

### Before filtering (server-native exposure)

```yaml
mcp_servers:
  github:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "***"
```

### After allowlist filtering

```yaml
mcp_servers:
  github:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "***"
    tools:
      include: [list_issues, create_issue, search_code]
      resources: false
      prompts: false
```

### After denylist filtering (HTTP MCP server)

```yaml
mcp_servers:
  stripe:
    url: "https://mcp.stripe.com"
    headers:
      Authorization: "Bearer ***"
    tools:
      exclude: [delete_customer, refund_payment]
```

If both `include` and `exclude` are set, `include` wins per the Hermes
config reference.

## This is not runtime enforcement

Lurkr is a pre-runtime, static, local-only check. It does not sit between
Hermes and the MCP server at request time, it does not approve or block live
tool calls, and it does not replace any of Hermes' own controls.

Runtime mediation of MCP tool calls is the responsibility of:

- Hermes' own configuration (`tools.include` / `tools.exclude`, plus any
  built-in approval or permission features tracked by Hermes itself — see
  e.g. [hermes-agent#16462](https://github.com/NousResearch/hermes-agent/issues/16462)
  and [hermes-agent#21849](https://github.com/NousResearch/hermes-agent/issues/21849));
- the MCP server's own permission model;
- and, optionally, an external runtime gateway (see the AgentVeil note
  below).

## Privacy and limitations

Lurkr is designed to stay out of the runtime path and out of your data:

- local-only scan; no source upload to AgentVeil;
- no network calls during `lurkr scan`;
- does not execute scanned project code;
- writes output only to the report path you provide;
- reports are redacted: raw secrets, command bodies, and key material are
  not included.

Limitations to keep in mind when using the report for Hermes filter
decisions:

- Lurkr is a bounded static scanner, not a complete security review. Some
  rules can produce false positives or false negatives.
- TypeScript / JavaScript coverage is restricted to canonical MCP
  `registerTool` registration shapes with bounded same-file and
  relative-path cross-file handler resolution. See
  [docs/LURKR_LIMITATIONS.md](../LURKR_LIMITATIONS.md) for the exact scope.
- The report describes capabilities present in the *source*; it does not
  describe runtime behavior, deployment environment, or downstream
  permissions of the credentials that Hermes will pass to the server.

## What this guide does not do

- It does not modify Hermes core behavior or replace Hermes controls.
- It does not make safety claims about Hermes.
- It does not auto-block any MCP tool call.
- It does not analyze prompt-injection risk inside MCP tool responses.
- It does not generate runtime evidence of what the agent actually did.

## Optional later path: external action-control layer

For high-risk MCP tools — anything where you want verifiable evidence for
configured high-risk calls, or a typed approval step outside the model's
own logs — you can later place an external action-control proxy between
Hermes and the MCP server. Hermes' config stays unchanged in shape:
you point the server URL at the proxy, and the proxy applies the policy
and writes evidence.

AgentVeil is one such layer. Details are out of scope for this guide; this
section exists only to note that pre-enable visibility (Lurkr) and
runtime action control are two distinct steps that can be adopted
independently.

## References

Hermes:

- [MCP with Hermes — guide](https://hermes-agent.nousresearch.com/docs/guides/use-mcp-with-hermes/)
- [MCP config reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference/)
- Issue: [first-invoke approval for MCP server tools (#16462)](https://github.com/NousResearch/hermes-agent/issues/16462)
- Issue: [tool permission gating system (#21849)](https://github.com/NousResearch/hermes-agent/issues/21849)

Lurkr:

- [Repository](https://github.com/agentveil-protocol/lurkr)
- [Detection scope](../../README.md#detection-scope)
- [Privacy & data handling](../../README.md#privacy--data-handling)
- [Known limitations](../LURKR_LIMITATIONS.md)

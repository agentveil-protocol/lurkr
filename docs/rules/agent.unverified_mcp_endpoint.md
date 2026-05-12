# agent.unverified_mcp_endpoint

Detects MCP server URLs that point to non-allowlisted external hosts. This
surfaces remote MCP dependencies that deserve an explicit trust review before
deployment.

## What It Flags

This rule parses supported MCP manifest files and reports URL-bearing MCP
server entries whose host is not built into Lurkr's local-development
allowlist. It checks MCP server fields such as `url`, `serverUrl`, `endpoint`,
`httpUrl`, and `wsUrl`.

The built-in allowlist covers local and development endpoints:

- `localhost`, `127.0.0.1`, `::1`, and `0.0.0.0`
- RFC1918 private IP ranges and other non-public IP spaces
- `*.local`
- `host.docker.internal`
- `stdio` and `pipe` transports without remote URL endpoints

Cloud-hosted or otherwise public MCP endpoints are reported even when they use
HTTPS. Lurkr v0.2.2 intentionally treats every external MCP connection as a
review checkpoint.

## Why It Matters

An MCP server is not just a URL. It can define tools, shape model context, and
influence the agent's reachable capability surface. A remote MCP server that
appears in a manifest without review can become an untrusted dependency for
server-side prompt injection, tool poisoning, or unexpected data access.

This rule makes the external trust boundary visible before deployment.

## Triggers

Bad:

```json
{
  "mcpServers": {
    "prod-search": {
      "url": "https://mcp.example.com/sse"
    }
  }
}
```

The MCP endpoint uses a public external host. Lurkr reports the manifest entry.

Good:

```json
{
  "mcpServers": {
    "local-search": {
      "url": "http://localhost:8765/sse"
    },
    "filesystem": {
      "command": "mcp-server-filesystem",
      "args": ["."]
    }
  }
}
```

The URL points to localhost and the second server uses stdio transport, so this
rule does not fire.

## Known Limitations

- The allowlist is built in for v0.2.2. User-configurable allowlists are a
  v0.3 candidate.
- The rule does not verify DNS ownership, certificates, server identity, or
  tool schemas. It only surfaces the external endpoint for review.
- Off-spec MCP manifests may not be parsed if the server list or URL fields do
  not match supported schema locations.
- A private IP endpoint is treated as clean, but private network trust still
  requires architecture review.

## Remediation

Verify the MCP server identity, transport security, tool surface, and ownership
before deployment. Document the trust justification for self-hosted servers.
For external servers, consider pinning versions, constraining the tool set, and
sandboxing the connection so a compromised MCP server cannot expand the
agent's authority unexpectedly.

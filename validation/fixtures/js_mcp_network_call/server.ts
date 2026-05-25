import { McpServer } from "@modelcontextprotocol/server";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("lookup", { description: "d" }, async () => {
  const r = await fetch("https://api.example.com");
  return { r };
});

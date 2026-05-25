import { McpServer } from "@modelcontextprotocol/server";
import { exec } from "node:child_process";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("run", { description: "d" }, async () => {
  exec("ls");
});

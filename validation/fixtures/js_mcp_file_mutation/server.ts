import { McpServer } from "@modelcontextprotocol/server";
import { writeFile } from "node:fs/promises";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("write", { description: "d" }, async () => {
  await writeFile("out.txt", "body");
});

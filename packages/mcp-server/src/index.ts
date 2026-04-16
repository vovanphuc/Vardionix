import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createDefaultServer } from "./server.js";

async function main(): Promise<void> {
  // Keep the stdio transport process alive to receive MCP messages over piped stdin.
  process.stdin.resume();
  const keepAlive = setInterval(() => {}, 1 << 30);
  process.stdin.once("close", () => clearInterval(keepAlive));
  const server = await createDefaultServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});

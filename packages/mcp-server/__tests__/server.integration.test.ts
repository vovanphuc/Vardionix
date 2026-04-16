import { beforeEach, describe, expect, it, vi } from "vitest";

const serverState = vi.hoisted(() => ({
  createdServers: [] as Array<{ registeredTools: string[]; name: string; version: string }>,
  context: {
    scanService: { marker: "scan" },
    explainService: { marker: "explain" },
  },
}));

vi.mock("@vardionix/core", () => ({
  createAppContext: () => serverState.context,
}));

vi.mock("@modelcontextprotocol/sdk/server/mcp.js", () => ({
  McpServer: class FakeMcpServer {
    registeredTools: string[] = [];

    constructor(public info: { name: string; version: string }) {
      serverState.createdServers.push({
        registeredTools: this.registeredTools,
        name: info.name,
        version: info.version,
      });
    }

    tool(name: string) {
      this.registeredTools.push(name);
    }
  },
}));

import { createServer } from "../src/server.js";

describe("MCP server integration", () => {
  beforeEach(() => {
    serverState.createdServers.length = 0;
  });

  it("registers the supported tool surface on startup", () => {
    createServer();

    expect(serverState.createdServers).toHaveLength(1);
    expect(serverState.createdServers[0]).toMatchObject({
      name: "vardionix",
      version: "0.1.0",
    });
    expect(serverState.createdServers[0].registeredTools).toEqual([
      "semgrep_scan",
      "findings_enrich",
      "finding_explain",
      "policy_lookup",
    ]);
  });
});

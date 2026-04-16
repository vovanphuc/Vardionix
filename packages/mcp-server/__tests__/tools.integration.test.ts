import { describe, expect, it, vi } from "vitest";
import { registerSemgrepScan } from "../src/tools/semgrep-scan.js";
import { registerFindingsEnrich } from "../src/tools/findings-enrich.js";
import { registerFindingExplain } from "../src/tools/finding-explain.js";
import { registerPolicyLookup } from "../src/tools/policy-lookup.js";

type ToolHandler = (args: Record<string, unknown>) => Promise<unknown>;

class FakeServer {
  handlers = new Map<string, ToolHandler>();

  tool(name: string, _description: string, _schema: unknown, handler: ToolHandler): void {
    this.handlers.set(name, handler);
  }
}

describe("MCP tool integration", () => {
  it("serializes scan summaries with excluded finding metadata", async () => {
    const server = new FakeServer();
    const scanService = {
      scan: vi.fn(async () => ({
        scanId: "S-20260416-abc123",
        startedAt: "2026-04-16T00:00:00.000Z",
        completedAt: "2026-04-16T00:00:01.000Z",
        target: "/repo",
        scope: "workspace",
        totalFindings: 2,
        totalExcluded: 1,
        findingsBySeverity: {
          critical: 0,
          high: 1,
          medium: 1,
          low: 0,
          info: 0,
        },
        excludedByReason: {
          "Low confidence": 1,
        },
        findingIds: ["F-1", "F-2"],
        excludedFindingIds: ["F-3"],
      })),
    };

    registerSemgrepScan(server as never, scanService as never);
    const result = await server.handlers.get("semgrep_scan")?.({
      scope: "workspace",
      ruleset: "auto",
      severityFilter: "high,medium",
    });

    expect(scanService.scan).toHaveBeenCalledWith({
      scope: "workspace",
      target: undefined,
      ruleset: "auto",
      severityFilter: ["high", "medium"],
    });
    const body = JSON.parse((result as any).content[0].text);
    expect(body.totalExcluded).toBe(1);
    expect(body.excludedFindingIds).toEqual(["F-3"]);
  });

  it("returns structured enrich results for open findings", async () => {
    const server = new FakeServer();
    const scanService = {
      enrichFindings: vi.fn(() => [
        { id: "F-1", policyId: "POL-001" },
      ]),
    };

    registerFindingsEnrich(server as never, scanService as never);
    const result = await server.handlers.get("findings_enrich")?.({
      findingIds: ["F-1"],
    });

    expect(scanService.enrichFindings).toHaveBeenCalledWith(["F-1"]);
    expect(JSON.parse((result as any).content[0].text)).toEqual({
      items: [{ id: "F-1", policyId: "POL-001" }],
    });
  });

  it("returns deterministic errors when explaining an excluded finding", async () => {
    const server = new FakeServer();
    const explainService = {
      explain: vi.fn(() => {
        throw new Error("Finding 'F-excluded' is excluded and cannot be explained: Low confidence");
      }),
    };

    registerFindingExplain(server as never, explainService as never);
    const result = await server.handlers.get("finding_explain")?.({
      findingId: "F-excluded",
    });

    expect((result as any).isError).toBe(true);
    expect((result as any).content[0].text).toContain("cannot be explained");
  });

  it("reports missing policies as MCP errors", async () => {
    const server = new FakeServer();
    const scanService = {
      getPolicyStore: vi.fn(() => ({
        getPolicy: vi.fn(() => null),
      })),
    };

    registerPolicyLookup(server as never, scanService as never);
    const result = await server.handlers.get("policy_lookup")?.({
      policyId: "POL-404",
    });

    expect((result as any).isError).toBe(true);
    expect((result as any).content[0].text).toContain("Policy 'POL-404' not found.");
  });
});

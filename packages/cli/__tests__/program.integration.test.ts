import { beforeEach, describe, expect, it, vi } from "vitest";
import { FindingStatus, Severity, type ActiveFinding, type ExcludedFinding } from "@vardionix/schemas";

const cliTestState = vi.hoisted(() => ({
  context: null as any,
}));

vi.mock("@vardionix/core", () => ({
  createAppContext: async () => cliTestState.context,
}));

import { createDefaultProgram } from "../src/program.js";

function makeActiveFinding(overrides: Partial<ActiveFinding> = {}): ActiveFinding {
  return {
    kind: "active",
    id: "F-active",
    ruleId: "javascript.lang.security.audit.xss",
    source: "semgrep",
    severity: Severity.HIGH,
    status: FindingStatus.OPEN,
    title: "Active finding",
    message: "Potential XSS",
    filePath: "src/app.js",
    startLine: 10,
    endLine: 10,
    firstSeenAt: "2026-04-16T00:00:00.000Z",
    lastSeenAt: "2026-04-16T00:00:00.000Z",
    confidenceScore: null,
    exploitScenario: null,
    category: null,
    policyId: null,
    policyTitle: null,
    policySeverityOverride: null,
    remediationGuidance: null,
    dismissedAt: null,
    dismissedReason: null,
    ...overrides,
  };
}

function makeExcludedFinding(overrides: Partial<ExcludedFinding> = {}): ExcludedFinding {
  return {
    kind: "excluded",
    id: "F-excluded",
    ruleId: "javascript.lang.security.audit.xss",
    source: "semgrep",
    severity: Severity.MEDIUM,
    title: "Excluded finding",
    message: "Excluded by filter",
    filePath: "src/ignored.js",
    startLine: 20,
    endLine: 20,
    firstSeenAt: "2026-04-16T00:00:00.000Z",
    lastSeenAt: "2026-04-16T00:00:00.000Z",
    confidenceScore: 0.4,
    exploitScenario: null,
    category: null,
    policyId: null,
    policyTitle: null,
    policySeverityOverride: null,
    remediationGuidance: null,
    exclusionReason: "Low confidence",
    excludedAt: "2026-04-16T00:00:01.000Z",
    ...overrides,
  };
}

function createMockContext() {
  const activeFindings = new Map<string, ActiveFinding>([
    ["F-active", makeActiveFinding()],
    ["F-reviewed", makeActiveFinding({
      id: "F-reviewed",
      status: FindingStatus.REVIEWED,
      title: "Reviewed finding",
    })],
  ]);
  const excludedFindings = new Map<string, ExcludedFinding>([
    ["F-excluded", makeExcludedFinding()],
  ]);

  return {
    findingsStore: {
      getFinding: (id: string) => activeFindings.get(id) ?? null,
      listFindings: (filters: Record<string, unknown> = {}) => {
        let items = Array.from(activeFindings.values());
        if (filters.status) {
          items = items.filter((finding) => finding.status === filters.status);
        }
        if (filters.severity) {
          items = items.filter((finding) => finding.severity === filters.severity);
        }
        if (typeof filters.limit === "number") {
          items = items.slice(0, filters.limit);
        }
        return items;
      },
      updateStatus: (id: string, status: FindingStatus, reason?: string) => {
        const finding = activeFindings.get(id);
        if (!finding) {
          return false;
        }
        activeFindings.set(id, {
          ...finding,
          status,
          dismissedReason: reason ?? null,
        });
        return true;
      },
    },
    excludedFindingsStore: {
      getFinding: (id: string) => excludedFindings.get(id) ?? null,
      listFindings: (filters: Record<string, unknown> = {}) => {
        let items = Array.from(excludedFindings.values());
        if (filters.severity) {
          items = items.filter((finding) => finding.severity === filters.severity);
        }
        if (typeof filters.limit === "number") {
          items = items.slice(0, filters.limit);
        }
        return items;
      },
    },
    scanService: {
      scan: vi.fn(async () => ({
        scanId: "S-20260416-abc123",
        startedAt: "2026-04-16T00:00:00.000Z",
        completedAt: "2026-04-16T00:00:01.000Z",
        target: "/repo",
        scope: "workspace",
        totalFindings: 1,
        totalExcluded: 1,
        findingsBySeverity: {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          info: 0,
        },
        excludedByReason: {
          "Low confidence": 1,
        },
        findingIds: ["F-active"],
        excludedFindingIds: ["F-excluded"],
      })),
      enrichFindings: vi.fn(() => []),
      getPolicyStore: vi.fn(() => ({
        getPolicy: vi.fn(() => null),
      })),
    },
    explainService: {
      explain: vi.fn((findingId: string) => {
        if (findingId === "F-active") {
          return {
            findingId,
            title: "Active finding",
            severity: "high",
            effectiveSeverity: "high",
            whyItMatters: "Potential XSS",
            whatToChange: ["Escape untrusted output"],
            safeExample: "Use output encoding",
          };
        }
        if (findingId === "F-excluded") {
          throw new Error("Finding 'F-excluded' is excluded and cannot be explained: Low confidence");
        }
        return null;
      }),
    },
    patchService: {
      generatePatchContext: vi.fn((findingId: string) => {
        if (findingId === "F-active") {
          return {
            findingId,
            finding: activeFindings.get("F-active"),
            prompt: "Fix the XSS",
            contextFiles: ["src/app.js"],
          };
        }
        if (findingId === "F-excluded") {
          throw new Error("Finding 'F-excluded' is excluded and cannot be patched: Low confidence");
        }
        return null;
      }),
    },
  };
}

async function runCli(args: string[]) {
  const stdout = vi.spyOn(console, "log").mockImplementation(() => {});
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  const previousExitCode = process.exitCode;
  process.exitCode = undefined;

  try {
    const program = await createDefaultProgram();
    await program.parseAsync(args, { from: "user" });

    return {
      stdout: stdout.mock.calls.map((call) => call.join(" ")).join("\n"),
      stderr: stderr.mock.calls.map((call) => call.join(" ")).join("\n"),
      exitCode: process.exitCode,
    };
  } finally {
    stdout.mockRestore();
    stderr.mockRestore();
    process.exitCode = previousExitCode;
  }
}

describe("CLI integration", () => {
  beforeEach(() => {
    cliTestState.context = createMockContext();
  });

  it("lists only active findings by default", async () => {
    const result = await runCli(["findings", "list", "--json"]);
    const findings = JSON.parse(result.stdout) as ActiveFinding[];

    expect(result.exitCode).toBeUndefined();
    expect(findings.map((finding) => finding.id)).toEqual(["F-active", "F-reviewed"]);
    expect(findings.every((finding) => finding.kind === "active")).toBe(true);
  });

  it("lists excluded findings separately", async () => {
    const result = await runCli(["findings", "list", "--excluded", "--json"]);
    const findings = JSON.parse(result.stdout) as ExcludedFinding[];

    expect(result.exitCode).toBeUndefined();
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("excluded");
    expect(findings[0].exclusionReason).toBe("Low confidence");
  });

  it("rejects mutually exclusive active and excluded filters", async () => {
    const result = await runCli(["findings", "list", "--open-only", "--excluded"]);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("Cannot combine --open-only with --excluded.");
  });

  it("shows excluded findings through the unified finding command", async () => {
    const result = await runCli(["finding", "show", "F-excluded", "--json"]);
    const finding = JSON.parse(result.stdout) as ExcludedFinding;

    expect(result.exitCode).toBeUndefined();
    expect(finding.kind).toBe("excluded");
    expect(finding.id).toBe("F-excluded");
  });

  it("returns excluded-aware errors from explain and patch commands", async () => {
    const explainResult = await runCli(["explain", "F-excluded", "--json"]);
    const patchResult = await runCli(["patch", "F-excluded", "--json"]);

    expect(explainResult.exitCode).toBe(1);
    expect(explainResult.stderr).toContain("is excluded and cannot be explained");
    expect(patchResult.exitCode).toBe(1);
    expect(patchResult.stderr).toContain("is excluded and cannot be patched");
  });

  it("surfaces the shared scan summary contract including excluded findings", async () => {
    const result = await runCli(["scan", "workspace", "--json"]);
    const summary = JSON.parse(result.stdout) as {
      totalFindings: number;
      totalExcluded: number;
      excludedFindingIds: string[];
    };

    expect(result.exitCode).toBeUndefined();
    expect(summary.totalFindings).toBe(1);
    expect(summary.totalExcluded).toBe(1);
    expect(summary.excludedFindingIds).toEqual(["F-excluded"]);
    expect(cliTestState.context.scanService.scan).toHaveBeenCalledWith({
      scope: "workspace",
      target: undefined,
      ruleset: "auto",
      severityFilter: undefined,
    });
  });
});

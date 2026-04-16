import { describe, expect, it } from "vitest";
import { FindingStatus, Severity, type ActiveFinding } from "@vardionix/schemas";
import { applyConfidenceThreshold } from "../../src/filter/findings-filter.js";

function makeFinding(overrides: Partial<ActiveFinding> = {}): ActiveFinding {
  return {
    kind: "active",
    id: "F-test",
    ruleId: "test.rule",
    source: "semgrep",
    severity: Severity.HIGH,
    status: FindingStatus.OPEN,
    title: "Test",
    message: "Test message",
    filePath: "src/app.js",
    startLine: 1,
    endLine: 1,
    firstSeenAt: "2026-04-15T00:00:00.000Z",
    lastSeenAt: "2026-04-15T00:00:00.000Z",
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

describe("applyConfidenceThreshold", () => {
  it("should keep findings without confidence metadata", () => {
    const result = applyConfidenceThreshold([makeFinding()], 0.8);
    expect(result.kept).toHaveLength(1);
    expect(result.excluded).toHaveLength(0);
  });

  it("should exclude findings below threshold", () => {
    const result = applyConfidenceThreshold([
      makeFinding({ confidenceScore: 0.5 }),
    ], 0.8);

    expect(result.kept).toHaveLength(0);
    expect(result.excluded).toHaveLength(1);
    expect(result.excluded[0].kind).toBe("excluded");
    expect(result.excluded[0].exclusionReason).toContain("Low confidence");
  });
});

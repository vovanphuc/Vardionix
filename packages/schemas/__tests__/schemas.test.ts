import { describe, it, expect } from "vitest";
import {
  FindingSchema,
  PolicySchema,
  ScanRequestSchema,
  ScanSummarySchema,
  Severity,
  FindingStatus,
  ScanScope,
} from "@vardionix/schemas";

describe("FindingSchema", () => {
  it("should parse a valid active finding", () => {
    const input = {
      id: "F-abc123def456",
      ruleId: "javascript.lang.security.audit.xss",
      source: "semgrep",
      severity: "high",
      status: "open",
      title: "XSS vulnerability",
      message: "Potential cross-site scripting",
      filePath: "src/app.js",
      startLine: 42,
      endLine: 42,
      firstSeenAt: "2026-04-15T00:00:00.000Z",
      lastSeenAt: "2026-04-15T00:00:00.000Z",
    };

    const result = FindingSchema.parse(input);
    expect(result.kind).toBe("active");
    expect(result.severity).toBe(Severity.HIGH);
    expect(result.status).toBe(FindingStatus.OPEN);
    expect(result.policyId).toBeNull();
  });

  it("should parse an excluded finding", () => {
    const input = {
      kind: "excluded",
      id: "F-test",
      ruleId: "test.rule",
      severity: "medium",
      title: "Test",
      message: "Test message",
      filePath: "test.js",
      startLine: 1,
      endLine: 1,
      firstSeenAt: "2026-04-15T00:00:00.000Z",
      lastSeenAt: "2026-04-15T00:00:00.000Z",
      exclusionReason: "Low confidence",
      excludedAt: "2026-04-16T00:00:00.000Z",
    };

    const result = FindingSchema.parse(input);
    expect(result.kind).toBe("excluded");
    expect(result.exclusionReason).toBe("Low confidence");
  });

  it("should set defaults for optional active fields", () => {
    const input = {
      id: "F-test",
      ruleId: "test.rule",
      severity: "medium",
      title: "Test",
      message: "Test message",
      filePath: "test.js",
      startLine: 1,
      endLine: 1,
      firstSeenAt: "2026-04-15T00:00:00.000Z",
      lastSeenAt: "2026-04-15T00:00:00.000Z",
    };

    const result = FindingSchema.parse(input);
    expect(result.kind).toBe("active");
    expect(result.source).toBe("semgrep");
    expect(result.status).toBe(FindingStatus.OPEN);
    expect(result.confidenceScore).toBeNull();
    expect(result.dismissedAt).toBeNull();
  });

  it("should reject invalid severity", () => {
    const input = {
      id: "F-test",
      ruleId: "test.rule",
      severity: "super-high",
      title: "Test",
      message: "Test message",
      filePath: "test.js",
      startLine: 1,
      endLine: 1,
      firstSeenAt: "2026-04-15T00:00:00.000Z",
      lastSeenAt: "2026-04-15T00:00:00.000Z",
    };

    expect(() => FindingSchema.parse(input)).toThrow();
  });
});

describe("PolicySchema", () => {
  it("should parse a valid policy", () => {
    const input = {
      id: "POL-001",
      title: "Test Policy",
      description: "A test policy",
      category: "OWASP-A03",
      rulePatterns: ["javascript.lang.security.*"],
      remediationGuidance: "Fix the issue",
    };

    const result = PolicySchema.parse(input);
    expect(result.id).toBe("POL-001");
    expect(result.references).toEqual([]);
    expect(result.severityOverride).toBeUndefined();
  });

  it("should parse policy with severity override", () => {
    const input = {
      id: "POL-002",
      title: "Critical Policy",
      description: "Critical",
      category: "CWE-89",
      severityOverride: "critical",
      rulePatterns: ["*.sql-injection.*"],
      remediationGuidance: "Use parameterized queries",
      references: ["https://example.com"],
    };

    const result = PolicySchema.parse(input);
    expect(result.severityOverride).toBe(Severity.CRITICAL);
    expect(result.references).toEqual(["https://example.com"]);
  });
});

describe("ScanRequestSchema", () => {
  it("should parse a valid scan request", () => {
    const input = {
      scope: "file",
      target: "src/app.js",
    };

    const result = ScanRequestSchema.parse(input);
    expect(result.scope).toBe(ScanScope.FILE);
    expect(result.ruleset).toBe("auto");
  });

  it("should accept severity filter", () => {
    const input = {
      scope: "staged",
      severityFilter: ["high", "critical"],
    };

    const result = ScanRequestSchema.parse(input);
    expect(result.severityFilter).toEqual([Severity.HIGH, Severity.CRITICAL]);
  });
});

describe("ScanSummarySchema", () => {
  it("should parse a scan summary with excluded findings", () => {
    const result = ScanSummarySchema.parse({
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
        "low-confidence": 1,
      },
      findingIds: ["F-1", "F-2"],
      excludedFindingIds: ["F-3"],
    });

    expect(result.totalExcluded).toBe(1);
    expect(result.excludedFindingIds).toEqual(["F-3"]);
  });
});

import { describe, it, expect } from "vitest";
import {
  FindingSchema,
  PolicySchema,
  JobSchema,
  ScanRequestSchema,
  Severity,
  FindingStatus,
  ScanScope,
  JobStatus,
} from "@vardionix/schemas";

describe("FindingSchema", () => {
  it("should parse a valid finding", () => {
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
    expect(result.id).toBe("F-abc123def456");
    expect(result.severity).toBe(Severity.HIGH);
    expect(result.status).toBe(FindingStatus.OPEN);
    expect(result.policyId).toBeNull();
  });

  it("should set defaults for optional fields", () => {
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
    expect(result.source).toBe("semgrep");
    expect(result.status).toBe(FindingStatus.OPEN);
    expect(result.policyId).toBeNull();
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

  it("should reject missing required fields", () => {
    expect(() => FindingSchema.parse({})).toThrow();
    expect(() => FindingSchema.parse({ id: "F-test" })).toThrow();
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

describe("JobSchema", () => {
  it("should parse a valid job", () => {
    const input = {
      id: "JOB-abc123",
      templateId: "go-sec-validate",
      status: "pending",
      createdAt: "2026-04-15T00:00:00.000Z",
    };

    const result = JobSchema.parse(input);
    expect(result.status).toBe(JobStatus.PENDING);
    expect(result.completedAt).toBeNull();
    expect(result.result).toBeNull();
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

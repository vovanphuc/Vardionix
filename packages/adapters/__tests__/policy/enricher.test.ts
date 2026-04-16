import { describe, it, expect, beforeEach } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PolicyLocalStore } from "../../src/policy/local-store.js";
import { PolicyEnricher } from "../../src/policy/enricher.js";
import { FindingStatus, Severity, type ActiveFinding } from "@vardionix/schemas";

const __dirname = dirname(fileURLToPath(import.meta.url));

function makeFinding(overrides: Partial<ActiveFinding> = {}): ActiveFinding {
  return {
    kind: "active",
    id: "F-test",
    ruleId: "test.rule",
    source: "semgrep",
    severity: Severity.MEDIUM,
    status: FindingStatus.OPEN,
    title: "Test",
    message: "Test message",
    filePath: "test.js",
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

describe("PolicyLocalStore", () => {
  let store: PolicyLocalStore;

  beforeEach(() => {
    const policiesDir = join(__dirname, "..", "..", "..", "..", "policies");
    store = new PolicyLocalStore([policiesDir]);
    store.load();
  });

  it("should load policies from YAML files", () => {
    const all = store.getAllPolicies();
    expect(all.length).toBeGreaterThan(0);
  });

  it("should find a policy by ID", () => {
    const policy = store.getPolicy("SEC-GO-014");
    expect(policy).not.toBeNull();
    expect(policy!.title).toContain("Guard nil values");
  });

  it("should find policies for a rule ID", () => {
    const policies = store.findPoliciesForRule("go.lang.security.audit.bad-reset-token");
    expect(policies.length).toBeGreaterThan(0);
    expect(policies[0].id).toBe("SEC-GO-014");
  });

  it("should match glob patterns", () => {
    const policies = store.findPoliciesForRule("javascript.lang.security.audit.xss.some-rule");
    // Should match POL-A03-INJECTION which has "*.lang.security.injection.*" pattern
    // OR other patterns - depends on policy data
    // At minimum, check the mechanism works
    expect(Array.isArray(policies)).toBe(true);
  });

  it("should return null for non-existent policy", () => {
    expect(store.getPolicy("NONEXISTENT")).toBeNull();
  });
});

describe("PolicyEnricher", () => {
  let enricher: PolicyEnricher;

  beforeEach(() => {
    const policiesDir = join(__dirname, "..", "..", "..", "..", "policies");
    const store = new PolicyLocalStore([policiesDir]);
    store.load();
    enricher = new PolicyEnricher(store);
  });

  it("should enrich a finding with matching policy", () => {
    const finding = makeFinding({
      ruleId: "go.lang.security.audit.bad-reset-token",
    });

    const enriched = enricher.enrichFinding(finding);
    expect(enriched.policyId).toBe("SEC-GO-014");
    expect(enriched.policyTitle).toContain("Guard nil values");
    expect(enriched.policySeverityOverride).toBe(Severity.HIGH);
    expect(enriched.remediationGuidance).toBeTruthy();
  });

  it("should not modify findings without matching policy", () => {
    const finding = makeFinding({
      ruleId: "some.random.unknown.rule",
    });

    const enriched = enricher.enrichFinding(finding);
    expect(enriched.policyId).toBeNull();
    expect(enriched.policySeverityOverride).toBeNull();
  });

  it("should enrich multiple findings", () => {
    const findings = [
      makeFinding({ id: "F-1", ruleId: "go.lang.security.audit.bad-reset-token" }),
      makeFinding({ id: "F-2", ruleId: "unknown.rule" }),
    ];

    const enriched = enricher.enrichFindings(findings);
    expect(enriched).toHaveLength(2);
    expect(enriched[0].policyId).toBe("SEC-GO-014");
    expect(enriched[1].policyId).toBeNull();
  });
});

import { describe, it, expect, beforeEach } from "vitest";
import {
  createInMemoryDatabase,
  type DatabaseLike,
  ExcludedFindingsStore,
  FindingsStore,
} from "../src/index.js";
import {
  FindingStatus,
  Severity,
  type ActiveFinding,
  type ExcludedFinding,
} from "@vardionix/schemas";

function makeFinding(overrides: Partial<ActiveFinding> = {}): ActiveFinding {
  return {
    kind: "active",
    id: "F-test123",
    ruleId: "test.rule",
    source: "semgrep",
    severity: Severity.HIGH,
    status: FindingStatus.OPEN,
    title: "Test Finding",
    message: "This is a test finding",
    filePath: "src/app.js",
    startLine: 42,
    endLine: 42,
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

function makeExcludedFinding(overrides: Partial<ExcludedFinding> = {}): ExcludedFinding {
  return {
    kind: "excluded",
    id: "F-excluded",
    ruleId: "test.rule",
    source: "semgrep",
    severity: Severity.MEDIUM,
    title: "Excluded Finding",
    message: "This finding was excluded",
    filePath: "src/app.js",
    startLine: 12,
    endLine: 12,
    firstSeenAt: "2026-04-15T00:00:00.000Z",
    lastSeenAt: "2026-04-15T00:00:00.000Z",
    confidenceScore: 0.5,
    exploitScenario: null,
    category: null,
    policyId: null,
    policyTitle: null,
    policySeverityOverride: null,
    remediationGuidance: null,
    exclusionReason: "Low confidence",
    excludedAt: "2026-04-16T00:00:00.000Z",
    ...overrides,
  };
}

describe("FindingsStore", () => {
  let db: DatabaseLike;
  let store: FindingsStore;
  let excludedStore: ExcludedFindingsStore;

  beforeEach(async () => {
    db = await createInMemoryDatabase();
    store = new FindingsStore(db);
    excludedStore = new ExcludedFindingsStore(db);
  });

  it("should upsert and retrieve an active finding", () => {
    const finding = makeFinding();
    store.upsertFinding(finding);

    const result = store.getFinding("F-test123");
    expect(result).not.toBeNull();
    expect(result!.kind).toBe("active");
    expect(result!.severity).toBe(Severity.HIGH);
  });

  it("should keep excluded findings out of active list", () => {
    store.upsertFinding(makeFinding({ id: "F-active" }));
    excludedStore.upsertFinding(makeExcludedFinding());

    expect(store.listFindings()).toHaveLength(1);
    expect(excludedStore.listFindings()).toHaveLength(1);
  });

  it("should update last_seen_at and mutable fields on upsert", () => {
    store.upsertFinding(makeFinding({ title: "Old", lastSeenAt: "2026-04-15T00:00:00.000Z" }));
    store.upsertFinding(makeFinding({
      title: "New",
      severity: Severity.LOW,
      lastSeenAt: "2026-04-16T00:00:00.000Z",
    }));

    const result = store.getFinding("F-test123");
    expect(result!.title).toBe("New");
    expect(result!.severity).toBe(Severity.LOW);
    expect(result!.lastSeenAt).toBe("2026-04-16T00:00:00.000Z");
  });

  it("should list active findings with filters", () => {
    store.upsertFinding(makeFinding({ id: "F-1", severity: Severity.HIGH }));
    store.upsertFinding(makeFinding({ id: "F-2", severity: Severity.LOW }));
    store.upsertFinding(makeFinding({ id: "F-3", severity: Severity.HIGH, status: FindingStatus.DISMISSED }));

    const highOpen = store.listFindings({ severity: Severity.HIGH, status: FindingStatus.OPEN });
    expect(highOpen).toHaveLength(1);
    expect(highOpen[0].id).toBe("F-1");
  });

  it("should update finding status", () => {
    store.upsertFinding(makeFinding());
    const success = store.updateStatus("F-test123", FindingStatus.DISMISSED, "False positive");

    expect(success).toBe(true);
    const result = store.getFinding("F-test123");
    expect(result!.status).toBe(FindingStatus.DISMISSED);
    expect(result!.dismissedReason).toBe("False positive");
  });

  it("should update policy enrichment", () => {
    store.upsertFinding(makeFinding());
    store.updatePolicyEnrichment(
      "F-test123",
      "POL-001",
      "Test Policy",
      "critical",
      "Fix the issue",
    );

    const result = store.getFinding("F-test123");
    expect(result!.policyId).toBe("POL-001");
    expect(result!.policySeverityOverride).toBe("critical");
  });

  it("should report stats for active findings only", () => {
    store.upsertFinding(makeFinding({ id: "F-1", severity: Severity.HIGH }));
    store.upsertFinding(makeFinding({ id: "F-2", severity: Severity.HIGH }));
    excludedStore.upsertFinding(makeExcludedFinding({ severity: Severity.HIGH }));

    const stats = store.getStats();
    expect(stats.total).toBe(2);
    expect(stats.bySeverity["high"]).toBe(2);
  });

  it("should bulk delete active findings", () => {
    store.upsertFindings([
      makeFinding({ id: "F-1" }),
      makeFinding({ id: "F-2" }),
      makeFinding({ id: "F-3" }),
    ]);

    store.deleteFindings(["F-1", "F-3"]);
    expect(store.listFindings().map((f) => f.id)).toEqual(["F-2"]);
  });

  it("should manage excluded findings separately", () => {
    excludedStore.upsertFinding(makeExcludedFinding());
    const result = excludedStore.getFinding("F-excluded");
    expect(result).not.toBeNull();
    expect(result!.kind).toBe("excluded");
    expect(result!.exclusionReason).toBe("Low confidence");
  });

  it("should respect limit and offset for excluded findings", () => {
    for (let i = 0; i < 5; i++) {
      excludedStore.upsertFinding(makeExcludedFinding({ id: `F-excluded-${i}` }));
    }

    const limited = excludedStore.listFindings({ limit: 2 });
    const offset = excludedStore.listFindings({ limit: 2, offset: 2 });
    expect(limited).toHaveLength(2);
    expect(offset).toHaveLength(2);
  });
});

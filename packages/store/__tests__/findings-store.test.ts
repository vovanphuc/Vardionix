import { describe, it, expect, beforeEach } from "vitest";
import Database from "better-sqlite3";
import { FindingsStore } from "../src/findings-store.js";
import { FindingStatus, Severity, type Finding } from "@vardionix/schemas";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function createTestDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("foreign_keys = ON");

  const migration = readFileSync(
    join(__dirname, "..", "src", "migrations", "001-init.sql"),
    "utf-8",
  );
  db.exec(migration);
  return db;
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
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
    policyId: null,
    policyTitle: null,
    policySeverityOverride: null,
    remediationGuidance: null,
    dismissedAt: null,
    dismissedReason: null,
    ...overrides,
  };
}

describe("FindingsStore", () => {
  let db: Database.Database;
  let store: FindingsStore;

  beforeEach(() => {
    db = createTestDb();
    store = new FindingsStore(db);
  });

  it("should upsert and retrieve a finding", () => {
    const finding = makeFinding();
    store.upsertFinding(finding);

    const result = store.getFinding("F-test123");
    expect(result).not.toBeNull();
    expect(result!.id).toBe("F-test123");
    expect(result!.ruleId).toBe("test.rule");
    expect(result!.severity).toBe(Severity.HIGH);
  });

  it("should return null for non-existent finding", () => {
    expect(store.getFinding("F-nonexistent")).toBeNull();
  });

  it("should update last_seen_at on upsert", () => {
    const finding1 = makeFinding({ lastSeenAt: "2026-04-15T00:00:00.000Z" });
    store.upsertFinding(finding1);

    const finding2 = makeFinding({ lastSeenAt: "2026-04-16T00:00:00.000Z" });
    store.upsertFinding(finding2);

    const result = store.getFinding("F-test123");
    expect(result!.lastSeenAt).toBe("2026-04-16T00:00:00.000Z");
  });

  it("should list findings with filters", () => {
    store.upsertFinding(makeFinding({ id: "F-1", severity: Severity.HIGH }));
    store.upsertFinding(makeFinding({ id: "F-2", severity: Severity.LOW }));
    store.upsertFinding(makeFinding({ id: "F-3", severity: Severity.HIGH, status: FindingStatus.DISMISSED }));

    const highOpen = store.listFindings({ severity: Severity.HIGH, status: FindingStatus.OPEN });
    expect(highOpen).toHaveLength(1);
    expect(highOpen[0].id).toBe("F-1");

    const allOpen = store.listFindings({ status: FindingStatus.OPEN });
    expect(allOpen).toHaveLength(2);
  });

  it("should update finding status", () => {
    store.upsertFinding(makeFinding());
    const success = store.updateStatus("F-test123", FindingStatus.DISMISSED, "False positive");

    expect(success).toBe(true);
    const result = store.getFinding("F-test123");
    expect(result!.status).toBe(FindingStatus.DISMISSED);
    expect(result!.dismissedReason).toBe("False positive");
    expect(result!.dismissedAt).not.toBeNull();
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
    expect(result!.policyTitle).toBe("Test Policy");
    expect(result!.policySeverityOverride).toBe("critical");
    expect(result!.remediationGuidance).toBe("Fix the issue");
  });

  it("should get stats", () => {
    store.upsertFinding(makeFinding({ id: "F-1", severity: Severity.HIGH }));
    store.upsertFinding(makeFinding({ id: "F-2", severity: Severity.HIGH }));
    store.upsertFinding(makeFinding({ id: "F-3", severity: Severity.LOW }));

    const stats = store.getStats();
    expect(stats.total).toBe(3);
    expect(stats.bySeverity["high"]).toBe(2);
    expect(stats.bySeverity["low"]).toBe(1);
  });

  it("should bulk upsert findings", () => {
    const findings = [
      makeFinding({ id: "F-1" }),
      makeFinding({ id: "F-2" }),
      makeFinding({ id: "F-3" }),
    ];
    store.upsertFindings(findings);

    const all = store.listFindings();
    expect(all).toHaveLength(3);
  });

  it("should delete a finding", () => {
    store.upsertFinding(makeFinding());
    expect(store.deleteFinding("F-test123")).toBe(true);
    expect(store.getFinding("F-test123")).toBeNull();
    expect(store.deleteFinding("F-nonexistent")).toBe(false);
  });

  it("should respect limit and offset", () => {
    for (let i = 0; i < 10; i++) {
      store.upsertFinding(makeFinding({ id: `F-${i}` }));
    }

    const limited = store.listFindings({ limit: 3 });
    expect(limited).toHaveLength(3);

    const offsetted = store.listFindings({ limit: 3, offset: 3 });
    expect(offsetted).toHaveLength(3);
    expect(offsetted[0].id).not.toBe(limited[0].id);
  });
});

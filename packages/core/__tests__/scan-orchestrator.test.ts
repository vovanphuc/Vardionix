import { describe, expect, it, vi } from "vitest";
import { resolve } from "node:path";
import { PolicyEnricher, PolicyLocalStore } from "@vardionix/adapters";
import {
  type ActiveFinding,
  type ExcludedFinding,
  FindingStatus,
  ScanScope,
  Severity,
} from "@vardionix/schemas";
import {
  createInMemoryDatabase,
  ExcludedFindingsStore,
  FindingsStore,
} from "@vardionix/store";
import { ScanService, type VardionixConfig } from "../src/index.js";

function makeActiveFinding(overrides: Partial<ActiveFinding> = {}): ActiveFinding {
  return {
    kind: "active",
    id: "F-active",
    ruleId: "python.lang.security.audit.pickle.loads",
    source: "semgrep",
    severity: Severity.HIGH,
    status: FindingStatus.OPEN,
    title: "Unsafe pickle deserialization",
    message: "Untrusted data is deserialized with pickle.loads.",
    filePath: resolve("/repo/src/app.py"),
    startLine: 12,
    endLine: 12,
    startCol: 1,
    endCol: 20,
    codeSnippet: "pickle.loads(user_supplied_bytes)",
    metadata: {},
    firstSeenAt: "2026-04-16T00:00:00.000Z",
    lastSeenAt: "2026-04-16T00:00:00.000Z",
    confidenceScore: 0.95,
    exploitScenario: null,
    category: "code-execution",
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
    ruleId: "python.lang.security.audit.pickle.loads",
    source: "semgrep",
    severity: Severity.MEDIUM,
    title: "Filtered pickle finding",
    message: "Candidate finding excluded during filtering.",
    filePath: resolve("/repo/src/app.py"),
    startLine: 12,
    endLine: 12,
    startCol: null,
    endCol: null,
    codeSnippet: null,
    metadata: {},
    firstSeenAt: "2026-04-16T00:00:00.000Z",
    lastSeenAt: "2026-04-16T00:00:00.000Z",
    confidenceScore: 0.3,
    exploitScenario: null,
    category: "code-execution",
    policyId: null,
    policyTitle: null,
    policySeverityOverride: null,
    remediationGuidance: null,
    exclusionReason: "Low confidence",
    excludedAt: "2026-04-16T00:00:01.000Z",
    ...overrides,
  };
}

describe("ScanService", () => {
  it("removes stale findings from the scanned file when a rescan comes back clean", async () => {
    const db = await createInMemoryDatabase();
    const findingsStore = new FindingsStore(db);
    const excludedFindingsStore = new ExcludedFindingsStore(db);
    const policyStore = new PolicyLocalStore([resolve(process.cwd(), "policies")]);
    policyStore.load();

    const config: VardionixConfig = {
      semgrep: {
        path: "semgrep",
        defaultRuleset: "auto",
        timeout: 300,
      },
      policy: {
        directories: [resolve(process.cwd(), "policies")],
      },
      output: {
        defaultFormat: "json",
        color: false,
      },
    };

    const scanService = new ScanService(
      config,
      findingsStore,
      excludedFindingsStore,
      policyStore,
      new PolicyEnricher(policyStore),
    );

    const scannedFile = resolve("/repo/src/app.py");
    findingsStore.upsertFinding(makeActiveFinding({ id: "F-stale", filePath: scannedFile }));
    findingsStore.upsertFinding(
      makeActiveFinding({ id: "F-other-file", filePath: resolve("/repo/src/other.py") }),
    );
    excludedFindingsStore.upsertFinding(
      makeExcludedFinding({ id: "F-excluded-stale", filePath: scannedFile }),
    );

    vi.spyOn((scanService as any).semgrepScanService, "scan").mockResolvedValue([]);

    const result = await scanService.scan({
      scope: ScanScope.FILE,
      target: scannedFile,
      ruleset: "auto",
    });

    expect(result.totalFindings).toBe(0);
    expect(findingsStore.getFinding("F-stale")).toBeNull();
    expect(excludedFindingsStore.getFinding("F-excluded-stale")).toBeNull();
    expect(findingsStore.getFinding("F-other-file")?.filePath).toBe(resolve("/repo/src/other.py"));
  });
});

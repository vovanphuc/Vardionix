import { beforeEach, describe, expect, it, vi } from "vitest";
import { resolve } from "node:path";
import { PolicyEnricher, PolicyLocalStore } from "@vardionix/adapters";
import {
  ExplainService,
  PatchService,
  ScanService,
  type VardionixAppContext,
  type VardionixConfig,
} from "@vardionix/core";
import {
  FindingStatus,
  Severity,
  type ActiveFinding,
  type ExcludedFinding,
} from "@vardionix/schemas";
import {
  ExcludedFindingsStore,
  FindingsStore,
  createInMemoryDatabase,
} from "@vardionix/store";
import { createProgram } from "../src/program.js";

const POLICIES_DIR = resolve(process.cwd(), "policies");

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
    filePath: "src/app.py",
    startLine: 12,
    endLine: 12,
    startCol: 1,
    endCol: 20,
    codeSnippet: "pickle.loads(user_supplied_bytes)",
    metadata: {},
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
    ruleId: "python.lang.security.audit.pickle.loads",
    source: "semgrep",
    severity: Severity.MEDIUM,
    title: "Filtered pickle finding",
    message: "Candidate finding excluded during filtering.",
    filePath: "src/ignored.py",
    startLine: 33,
    endLine: 33,
    startCol: null,
    endCol: null,
    codeSnippet: null,
    metadata: {},
    firstSeenAt: "2026-04-16T00:00:00.000Z",
    lastSeenAt: "2026-04-16T00:00:00.000Z",
    confidenceScore: 0.3,
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

async function createRealContext(): Promise<VardionixAppContext> {
  const db = await createInMemoryDatabase();
  const findingsStore = new FindingsStore(db);
  const excludedFindingsStore = new ExcludedFindingsStore(db);
  const policyStore = new PolicyLocalStore([POLICIES_DIR]);
  policyStore.load();
  const policyEnricher = new PolicyEnricher(policyStore);

  const config: VardionixConfig = {
    semgrep: {
      path: "semgrep",
      defaultRuleset: "auto",
      timeout: 300,
    },
    policy: {
      directories: [POLICIES_DIR],
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
    policyEnricher,
  );
  const explainService = new ExplainService(findingsStore, excludedFindingsStore);
  const patchService = new PatchService(findingsStore, excludedFindingsStore);

  const activeFinding = makeActiveFinding();
  findingsStore.upsertFinding(activeFinding);
  findingsStore.upsertFinding(
    makeActiveFinding({
      id: "F-dismissed",
      status: FindingStatus.DISMISSED,
      title: "Dismissed finding",
    }),
  );
  excludedFindingsStore.upsertFinding(makeExcludedFinding());
  scanService.enrichFindings([activeFinding.id]);

  return {
    config,
    findingsStore,
    excludedFindingsStore,
    policyStore,
    policyEnricher,
    scanService,
    explainService,
    patchService,
  };
}

async function runCli(args: string[], context: VardionixAppContext) {
  const stdout = vi.spyOn(console, "log").mockImplementation(() => {});
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  const previousExitCode = process.exitCode;
  process.exitCode = undefined;

  try {
    const program = createProgram(context);
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

describe("CLI integration with real services", () => {
  let context: VardionixAppContext;

  beforeEach(async () => {
    context = await createRealContext();
  });

  it("shows built-in policy data through the real policy store", async () => {
    const result = await runCli(["policy", "show", "POL-A03-INJECTION", "--json"], context);
    const policy = JSON.parse(result.stdout) as {
      id: string;
      category: string;
      severityOverride?: string;
    };

    expect(result.exitCode).toBeUndefined();
    expect(policy).toMatchObject({
      id: "POL-A03-INJECTION",
      category: "OWASP-A03",
      severityOverride: "critical",
    });
  });

  it("builds explanations from the real explain service and enriched finding data", async () => {
    const result = await runCli(["explain", "F-active", "--json"], context);
    const explanation = JSON.parse(result.stdout) as {
      effectiveSeverity: string;
      whatToChange: string[];
      policyContext?: { policyId: string };
    };

    expect(result.exitCode).toBeUndefined();
    expect(explanation.effectiveSeverity).toBe("critical");
    expect(explanation.policyContext?.policyId).toBe("SEC-PY-003");
    expect(explanation.whatToChange.length).toBeGreaterThan(0);
  });

  it("updates the real findings store when dismissing an active finding", async () => {
    const result = await runCli(
      ["finding", "dismiss", "F-active", "--reason", "Accepted risk"],
      context,
    );
    const finding = context.findingsStore.getFinding("F-active");

    expect(result.exitCode).toBeUndefined();
    expect(result.stdout).toContain("Finding F-active dismissed.");
    expect(finding?.status).toBe(FindingStatus.DISMISSED);
    expect(finding?.dismissedReason).toBe("Accepted risk");
  });

  it("keeps excluded findings outside codex batch-fix results", async () => {
    const result = await runCli(
      ["agent", "codex", "batch-fix", "--severity", "high", "--json"],
      context,
    );
    const contexts = JSON.parse(result.stdout) as Array<{ findingId: string }>;

    expect(result.exitCode).toBeUndefined();
    expect(contexts.map((item) => item.findingId)).toEqual(["F-active"]);
  });

  it("returns an explicit real-service error for excluded patch requests", async () => {
    const result = await runCli(["patch", "F-excluded", "--json"], context);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain(
      "Finding 'F-excluded' is excluded and cannot be patched: Low confidence",
    );
  });
});

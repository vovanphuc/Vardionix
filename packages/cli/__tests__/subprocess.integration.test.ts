import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { execFile, spawn } from "node:child_process";
import { mkdtemp, mkdir, open, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import {
  closeDatabase,
  createInMemoryDatabase,
  ExcludedFindingsStore,
  FindingsStore,
  getDatabase,
} from "@vardionix/store";
import {
  FindingStatus,
  Severity,
  type ActiveFinding,
  type ExcludedFinding,
} from "@vardionix/schemas";

const repoRoot = resolve(process.cwd());
const cliEntry = resolve(repoRoot, "packages/cli/dist/index.js");

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
    policyId: "SEC-PY-003",
    policyTitle: "Avoid unsafe pickle deserialization",
    policySeverityOverride: Severity.CRITICAL,
    remediationGuidance: "Replace pickle.loads with json.loads for untrusted data.",
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

async function createSeededHomeDir(): Promise<string> {
  const homeDir = await mkdtemp(join(tmpdir(), "vardionix-cli-e2e-"));
  const vardionixDir = join(homeDir, ".vardionix");
  const dbPath = join(vardionixDir, "findings.db");

  await mkdir(vardionixDir, { recursive: true });

  const db = await createInMemoryDatabase();
  const findingsStore = new FindingsStore(db);
  const excludedFindingsStore = new ExcludedFindingsStore(db);

  findingsStore.upsertFinding(makeActiveFinding());
  excludedFindingsStore.upsertFinding(makeExcludedFinding());
  db.close();

  closeDatabase();
  const persistedDb = await getDatabase(dbPath);
  new FindingsStore(persistedDb).upsertFinding(makeActiveFinding());
  new ExcludedFindingsStore(persistedDb).upsertFinding(makeExcludedFinding());
  closeDatabase();

  return homeDir;
}

async function runCliSubprocess(
  args: string[],
  homeDir: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const stdoutPath = join(homeDir, "stdout.log");
  const stderrPath = join(homeDir, "stderr.log");
  const stdoutFile = await open(stdoutPath, "w");
  const stderrFile = await open(stderrPath, "w");

  return new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [cliEntry, ...args],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          HOME: homeDir,
          NO_COLOR: "1",
          FORCE_COLOR: "0",
        },
        stdio: ["ignore", stdoutFile.fd, stderrFile.fd],
      },
    );

    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
    }, 120_000);

    child.on("error", async (error) => {
      clearTimeout(timeout);
      await stdoutFile.close();
      await stderrFile.close();
      reject(error);
    });

    child.on("close", async (code) => {
      clearTimeout(timeout);
      await stdoutFile.close();
      await stderrFile.close();
      try {
        const [stdout, stderr] = await Promise.all([
          readFile(stdoutPath, "utf8"),
          readFile(stderrPath, "utf8"),
        ]);
        resolvePromise({ code, stdout, stderr });
      } catch (error) {
          reject(error);
      }
      },
    );
  });
}

const tempHomes: string[] = [];

beforeAll(async () => {
  await new Promise<void>((resolvePromise, reject) => {
    execFile(
      "npm",
      ["run", "build", "--workspace", "packages/cli"],
      {
        cwd: repoRoot,
        env: process.env,
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      },
      (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolvePromise();
      },
    );
  });
});

afterEach(async () => {
  await Promise.all(tempHomes.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("CLI subprocess integration", () => {
  it("reads active and excluded findings from a real seeded sqlite file", async () => {
    const homeDir = await createSeededHomeDir();
    tempHomes.push(homeDir);

    const active = await runCliSubprocess(["findings", "list", "--json"], homeDir);
    const excluded = await runCliSubprocess(["findings", "list", "--excluded", "--json"], homeDir);

    expect(active.code).toBe(0);
    expect(excluded.code).toBe(0);

    expect(JSON.parse(active.stdout)).toEqual([
      expect.objectContaining({ id: "F-active", kind: "active" }),
    ]);
    expect(JSON.parse(excluded.stdout)).toEqual([
      expect.objectContaining({ id: "F-excluded", kind: "excluded" }),
    ]);
  });

  it("persists status changes across separate CLI subprocesses", async () => {
    const homeDir = await createSeededHomeDir();
    tempHomes.push(homeDir);

    const dismiss = await runCliSubprocess(
      ["finding", "dismiss", "F-active", "--reason", "Accepted risk"],
      homeDir,
    );
    const show = await runCliSubprocess(["finding", "show", "F-active", "--json"], homeDir);

    expect(dismiss.code).toBe(0);
    expect(dismiss.stdout).toContain("Finding F-active dismissed.");
    expect(show.code).toBe(0);
    expect(JSON.parse(show.stdout)).toEqual(
      expect.objectContaining({
        id: "F-active",
        status: "dismissed",
        dismissedReason: "Accepted risk",
      }),
    );
  });

  it("returns excluded-finding errors from a real CLI subprocess", async () => {
    const homeDir = await createSeededHomeDir();
    tempHomes.push(homeDir);

    const result = await runCliSubprocess(["explain", "F-excluded", "--json"], homeDir);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "Finding 'F-excluded' is excluded and cannot be explained: Low confidence",
    );
  });
});

import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { PassThrough } from "node:stream";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  createInMemoryDatabase,
  ExcludedFindingsStore,
  FindingsStore,
} from "@vardionix/store";
import {
  ExplainService,
  PatchService,
  ScanService,
  type VardionixAppContext,
  type VardionixConfig,
} from "@vardionix/core";
import { PolicyEnricher, PolicyLocalStore } from "@vardionix/adapters";
import {
  FindingStatus,
  Severity,
  type ActiveFinding,
  type ExcludedFinding,
} from "@vardionix/schemas";
import { createServer } from "../src/server.js";

const repoRoot = resolve(process.cwd());
const policiesDir = resolve(repoRoot, "policies");

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

class InProcessStdioClientTransport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: unknown) => void;

  private readBuffer = new ReadBuffer();

  constructor(
    private readonly input: PassThrough,
    private readonly output: PassThrough,
  ) {}

  async start(): Promise<void> {
    this.input.on("data", this.onData);
    this.input.on("error", this.onStreamError);
    this.input.on("close", this.onStreamClose);
  }

  async close(): Promise<void> {
    this.input.off("data", this.onData);
    this.input.off("error", this.onStreamError);
    this.input.off("close", this.onStreamClose);
    this.readBuffer.clear();
    this.output.end();
    this.onclose?.();
  }

  async send(message: unknown): Promise<void> {
    const json = serializeMessage(message);
    await new Promise<void>((resolvePromise) => {
      if (this.output.write(json)) {
        resolvePromise();
        return;
      }
      this.output.once("drain", resolvePromise);
    });
  }

  private onData = (chunk: Buffer): void => {
    this.readBuffer.append(chunk);
    while (true) {
      try {
        const message = this.readBuffer.readMessage();
        if (message === null) {
          break;
        }
        this.onmessage?.(message);
      } catch (error) {
        this.onerror?.(error as Error);
        break;
      }
    }
  };

  private onStreamError = (error: Error): void => {
    this.onerror?.(error);
  };

  private onStreamClose = (): void => {
    this.onclose?.();
  };
}

async function createAppContextForTransportTest(): Promise<VardionixAppContext> {
  const config: VardionixConfig = {
    semgrep: {
      path: "semgrep",
      defaultRuleset: "auto",
      timeout: 300,
    },
    policy: {
      directories: [policiesDir],
    },
    output: {
      defaultFormat: "json",
      color: false,
    },
  };

  const seededDb = await createInMemoryDatabase();
  const findingsStore = new FindingsStore(seededDb);
  const excludedFindingsStore = new ExcludedFindingsStore(seededDb);
  findingsStore.upsertFinding(makeActiveFinding());
  excludedFindingsStore.upsertFinding(makeExcludedFinding());

  const policyStore = new PolicyLocalStore([policiesDir]);
  policyStore.load();
  const policyEnricher = new PolicyEnricher(policyStore);
  const scanService = new ScanService(
    config,
    findingsStore,
    excludedFindingsStore,
    policyStore,
    policyEnricher,
  );
  const explainService = new ExplainService(findingsStore, excludedFindingsStore);
  const patchService = new PatchService(findingsStore, excludedFindingsStore);

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

describe("MCP stdio transport integration", () => {
  it("serves tools over stdio and returns real tool results", async () => {
    const clientToServer = new PassThrough();
    const serverToClient = new PassThrough();
    const server = createServer(await createAppContextForTransportTest());
    const serverTransport = new StdioServerTransport(clientToServer, serverToClient);
    await server.connect(serverTransport);

    const transport = new InProcessStdioClientTransport(serverToClient, clientToServer);
    const client = new Client({
      name: "vardionix-stdio-test",
      version: "0.0.0",
    });

    try {
      await client.connect(transport);

      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name)).toEqual(
        expect.arrayContaining([
          "semgrep_scan",
          "findings_enrich",
          "finding_explain",
          "policy_lookup",
        ]),
      );

      const explain = await client.callTool({
        name: "finding_explain",
        arguments: {
          findingId: "F-active",
        },
      });
      expect(JSON.parse((explain.content[0] as { text: string }).text)).toEqual(
        expect.objectContaining({
          findingId: "F-active",
          title: "Unsafe pickle deserialization",
        }),
      );

      const enrich = await client.callTool({
        name: "findings_enrich",
        arguments: {
          findingIds: ["F-active"],
        },
      });
      expect(JSON.parse((enrich.content[0] as { text: string }).text)).toEqual({
        items: [
          expect.objectContaining({
            id: "F-active",
            policyId: "SEC-PY-003",
            policySeverityOverride: "critical",
          }),
        ],
      });

      const excludedExplain = await client.callTool({
        name: "finding_explain",
        arguments: {
          findingId: "F-excluded",
        },
      });
      expect(excludedExplain.isError).toBe(true);
      expect((excludedExplain.content[0] as { text: string }).text).toContain(
        "cannot be explained: Low confidence",
      );
    } finally {
      await client.close();
    }
  });
});

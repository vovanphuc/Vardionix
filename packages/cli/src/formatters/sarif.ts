import type { ActiveFinding } from "@vardionix/schemas";

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  defaultConfiguration?: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        endLine: number;
        startColumn?: number;
        endColumn?: number;
      };
    };
  }>;
}

function severityToLevel(severity: string): string {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "note";
  }
}

export function formatSarif(findings: ActiveFinding[]): string {
  const ruleMap = new Map<string, SarifRule>();

  for (const f of findings) {
    if (!ruleMap.has(f.ruleId)) {
      ruleMap.set(f.ruleId, {
        id: f.ruleId,
        shortDescription: { text: f.title },
        defaultConfiguration: {
          level: severityToLevel(f.severity),
        },
      });
    }
  }

  const sarifLog: SarifLog = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "vardionix",
            version: "0.1.0",
            rules: Array.from(ruleMap.values()),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: severityToLevel(f.policySeverityOverride ?? f.severity),
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.filePath },
                region: {
                  startLine: f.startLine,
                  endLine: f.endLine,
                  startColumn: f.startCol,
                  endColumn: f.endCol,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
}

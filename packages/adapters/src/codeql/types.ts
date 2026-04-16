/** SARIF v2.1.0 types (subset relevant for CodeQL output) */

export interface SarifLog {
  version: string;
  $schema?: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: SarifToolDriver;
  };
  results: SarifResult[];
}

export interface SarifToolDriver {
  name: string;
  version?: string;
  rules?: SarifRule[];
}

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: { level?: string };
  properties?: {
    tags?: string[];
    precision?: string;
    "security-severity"?: string;
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level?: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations?: SarifLocation[];
  partialFingerprints?: Record<string, string>;
}

export interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: {
      uri: string;
      uriBaseId?: string;
    };
    region?: SarifRegion;
  };
}

export interface SarifRegion {
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
}

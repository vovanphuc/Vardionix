import type { TrivyJsonOutput, TrivyVulnerability } from "./types.js";

export interface ParsedTrivyVulnerability {
  vulnId: string;
  pkgName: string;
  pkgVersion: string;
  fixedVersion: string | null;
  severity: string;
  title: string;
  description: string;
  lockfile: string;
  ecosystem: string;
  cvssScore: number | null;
  cweIds: string[];
  references: string[];
  primaryUrl: string | null;
  publishedDate: string | null;
  status: string | null;
}

export function parseTrivyOutput(
  output: TrivyJsonOutput,
): ParsedTrivyVulnerability[] {
  const findings: ParsedTrivyVulnerability[] = [];

  for (const result of output.Results) {
    if (!result.Vulnerabilities) continue;

    for (const vuln of result.Vulnerabilities) {
      findings.push({
        vulnId: vuln.VulnerabilityID,
        pkgName: vuln.PkgName,
        pkgVersion: vuln.InstalledVersion,
        fixedVersion: vuln.FixedVersion || null,
        severity: mapSeverity(vuln.Severity),
        title: vuln.Title || `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
        description: vuln.Description || vuln.Title || "",
        lockfile: result.Target,
        ecosystem: result.Type,
        cvssScore: extractCvssScore(vuln.CVSS),
        cweIds: vuln.CweIDs ?? [],
        references: vuln.References ?? [],
        primaryUrl: vuln.PrimaryURL ?? null,
        publishedDate: vuln.PublishedDate ?? null,
        status: vuln.Status ?? null,
      });
    }
  }

  return findings;
}

function mapSeverity(severity: string): string {
  const map: Record<string, string> = {
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    UNKNOWN: "info",
  };
  return map[severity] ?? "info";
}

function extractCvssScore(
  cvss: TrivyVulnerability["CVSS"],
): number | null {
  if (!cvss) return null;
  for (const source of ["nvd", "ghsa", ...Object.keys(cvss)]) {
    if (cvss[source]?.V3Score) return cvss[source].V3Score;
  }
  return null;
}

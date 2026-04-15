import { z } from "zod";
import { FindingStatus, Severity } from "./enums.js";

export const FindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  source: z.string().default("semgrep"),
  severity: z.nativeEnum(Severity),
  status: z.nativeEnum(FindingStatus).default(FindingStatus.OPEN),
  title: z.string(),
  message: z.string(),
  filePath: z.string(),
  startLine: z.number().int(),
  endLine: z.number().int(),
  startCol: z.number().int().optional(),
  endCol: z.number().int().optional(),
  codeSnippet: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
  // Confidence & exploit context (inspired by claude-code-security-review)
  confidenceScore: z.number().min(0).max(1).nullable().default(null),
  exploitScenario: z.string().nullable().default(null),
  category: z
    .enum([
      "input-validation",
      "auth-bypass",
      "crypto-weakness",
      "code-execution",
      "data-exposure",
      "csrf",
      "ssrf",
      "path-traversal",
      "other",
    ])
    .nullable()
    .default(null),
  // False-positive filtering
  excluded: z.boolean().default(false),
  exclusionReason: z.string().nullable().default(null),
  policyId: z.string().nullable().default(null),
  policyTitle: z.string().nullable().default(null),
  policySeverityOverride: z.nativeEnum(Severity).nullable().default(null),
  remediationGuidance: z.string().nullable().default(null),
  firstSeenAt: z.string().datetime(),
  lastSeenAt: z.string().datetime(),
  dismissedAt: z.string().datetime().nullable().default(null),
  dismissedReason: z.string().nullable().default(null),
});

export type Finding = z.infer<typeof FindingSchema>;

import { z } from "zod";
import { FindingStatus, Severity } from "./enums.js";

const FindingCategorySchema = z
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
  .default(null);

export const BaseFindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  source: z.string().default("semgrep"),
  severity: z.nativeEnum(Severity),
  title: z.string(),
  message: z.string(),
  filePath: z.string(),
  startLine: z.number().int(),
  endLine: z.number().int(),
  startCol: z.number().int().optional(),
  endCol: z.number().int().optional(),
  codeSnippet: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
  confidenceScore: z.number().min(0).max(1).nullable().default(null),
  exploitScenario: z.string().nullable().default(null),
  category: FindingCategorySchema,
  policyId: z.string().nullable().default(null),
  policyTitle: z.string().nullable().default(null),
  policySeverityOverride: z.nativeEnum(Severity).nullable().default(null),
  remediationGuidance: z.string().nullable().default(null),
  firstSeenAt: z.string().datetime(),
  lastSeenAt: z.string().datetime(),
});

export const ActiveFindingSchema = BaseFindingSchema.extend({
  kind: z.literal("active").default("active"),
  status: z.nativeEnum(FindingStatus).default(FindingStatus.OPEN),
  dismissedAt: z.string().datetime().nullable().default(null),
  dismissedReason: z.string().nullable().default(null),
});

export const ExcludedFindingSchema = BaseFindingSchema.extend({
  kind: z.literal("excluded"),
  exclusionReason: z.string(),
  excludedAt: z.string().datetime(),
});

export const FindingSchema = z.union([
  ActiveFindingSchema,
  ExcludedFindingSchema,
]);

export type BaseFinding = z.infer<typeof BaseFindingSchema>;
export type ActiveFinding = z.infer<typeof ActiveFindingSchema>;
export type ExcludedFinding = z.infer<typeof ExcludedFindingSchema>;
export type Finding = z.infer<typeof FindingSchema>;

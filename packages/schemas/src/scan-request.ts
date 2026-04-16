import { z } from "zod";
import { ScanScope, Severity } from "./enums.js";

export const ScanRequestSchema = z.object({
  scope: z.nativeEnum(ScanScope),
  target: z.string().optional(),
  ruleset: z.string().default("auto"),
  severityFilter: z.array(z.nativeEnum(Severity)).optional(),
});

export type ScanRequest = z.infer<typeof ScanRequestSchema>;

const SeverityCountsSchema = z.record(z.nativeEnum(Severity), z.number().int());

export const ScanSummarySchema = z.object({
  scanId: z.string(),
  startedAt: z.string().datetime(),
  completedAt: z.string().datetime(),
  target: z.string(),
  scope: z.nativeEnum(ScanScope),
  totalFindings: z.number().int(),
  totalExcluded: z.number().int(),
  findingsBySeverity: SeverityCountsSchema,
  excludedByReason: z.record(z.string(), z.number().int()),
  findingIds: z.array(z.string()),
  excludedFindingIds: z.array(z.string()),
});

export const ScanResultSchema = ScanSummarySchema;

export type ScanSummary = z.infer<typeof ScanSummarySchema>;
export type ScanResult = ScanSummary;

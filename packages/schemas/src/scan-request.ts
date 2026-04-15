import { z } from "zod";
import { ScanScope, Severity } from "./enums.js";

export const ScanRequestSchema = z.object({
  scope: z.nativeEnum(ScanScope),
  target: z.string().optional(),
  ruleset: z.string().default("auto"),
  severityFilter: z.array(z.nativeEnum(Severity)).optional(),
});

export type ScanRequest = z.infer<typeof ScanRequestSchema>;

export const ScanResultSchema = z.object({
  scanId: z.string(),
  startedAt: z.string().datetime(),
  completedAt: z.string().datetime(),
  target: z.string(),
  scope: z.nativeEnum(ScanScope),
  totalFindings: z.number().int(),
  findingsBySeverity: z.record(z.nativeEnum(Severity), z.number().int()),
  findingIds: z.array(z.string()),
});

export type ScanResult = z.infer<typeof ScanResultSchema>;

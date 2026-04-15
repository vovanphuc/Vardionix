import { z } from "zod";
import { Severity } from "./enums.js";

export const PolicySchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  category: z.string(),
  severityOverride: z.nativeEnum(Severity).optional(),
  rulePatterns: z.array(z.string()),
  remediationGuidance: z.string(),
  references: z.array(z.string()).default([]),
});

export type Policy = z.infer<typeof PolicySchema>;

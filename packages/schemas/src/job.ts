import { z } from "zod";
import { JobStatus } from "./enums.js";

export const JobSchema = z.object({
  id: z.string(),
  templateId: z.string(),
  status: z.nativeEnum(JobStatus).default(JobStatus.PENDING),
  findingId: z.string().optional(),
  createdAt: z.string().datetime(),
  completedAt: z.string().datetime().nullable().default(null),
  result: z.unknown().nullable().default(null),
  logs: z.string().nullable().default(null),
});

export type Job = z.infer<typeof JobSchema>;

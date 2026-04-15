import { randomUUID } from "node:crypto";
import type { SubmitJobRequest, JobResult } from "./types.js";
import { isTemplateAllowed } from "./templates.js";

/**
 * Backend.AI client - stubbed for Phase 1 MVP.
 * In Phase 2, this will make real HTTP calls to Backend.AI Gateway.
 */
export class BackendAIClient {
  private jobs: Map<string, JobResult> = new Map();

  constructor(
    private _endpoint?: string,
    private _apiKey?: string,
  ) {}

  async submitJob(request: SubmitJobRequest): Promise<JobResult> {
    if (!isTemplateAllowed(request.templateId)) {
      throw new Error(
        `Template '${request.templateId}' is not in the allowed templates whitelist.`,
      );
    }

    // Stub: create a pending job
    const jobId = `JOB-${randomUUID().slice(0, 8)}`;
    const result: JobResult = {
      jobId,
      status: "pending",
      logsPreview:
        "[Phase 1 Stub] Backend.AI integration is not yet available. " +
        "Job has been queued locally for tracking purposes.",
    };

    this.jobs.set(jobId, result);
    return result;
  }

  async getJob(jobId: string): Promise<JobResult | null> {
    return this.jobs.get(jobId) ?? null;
  }
}

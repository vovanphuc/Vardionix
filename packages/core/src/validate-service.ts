import type { Job } from "@vardionix/schemas";
import { JobStatus } from "@vardionix/schemas";
import type { FindingsStore } from "@vardionix/store";
import { JobsStore } from "@vardionix/store";
import { BackendAIClient, isTemplateAllowed } from "@vardionix/adapters";
import type Database from "better-sqlite3";

export class ValidateService {
  private backendaiClient: BackendAIClient;
  private jobsStore: JobsStore;

  constructor(
    private findingsStore: FindingsStore,
    db: Database.Database,
    endpoint?: string,
    apiKey?: string,
  ) {
    this.backendaiClient = new BackendAIClient(endpoint, apiKey);
    this.jobsStore = new JobsStore(db);
  }

  async submitValidation(
    findingId: string,
    templateId: string,
    workspaceMeta?: { repo: string; branch: string },
  ): Promise<Job> {
    const finding = this.findingsStore.getFinding(findingId);
    if (!finding) {
      throw new Error(`Finding '${findingId}' not found.`);
    }

    if (!isTemplateAllowed(templateId)) {
      throw new Error(
        `Template '${templateId}' is not in the allowed templates whitelist.`,
      );
    }

    const result = await this.backendaiClient.submitJob({
      templateId,
      findingId,
      parameters: {},
      workspaceMeta,
    });

    const job: Job = {
      id: result.jobId,
      templateId,
      status: JobStatus.PENDING,
      findingId,
      createdAt: new Date().toISOString(),
      completedAt: null,
      result: null,
      logs: result.logsPreview ?? null,
    };

    this.jobsStore.insertJob(job);
    return job;
  }

  async getJob(jobId: string): Promise<Job | null> {
    // Check remote status first
    const remoteResult = await this.backendaiClient.getJob(jobId);
    if (remoteResult) {
      // Update local store
      const status = remoteResult.status as Job["status"];
      this.jobsStore.updateJobStatus(
        jobId,
        status,
        remoteResult.logsPreview,
        remoteResult,
      );
    }

    return this.jobsStore.getJob(jobId);
  }

  listJobs(findingId?: string): Job[] {
    return this.jobsStore.listJobs(findingId);
  }
}

export interface JobTemplate {
  id: string;
  name: string;
  description: string;
  language: string;
  parameters: TemplateParameter[];
}

export interface TemplateParameter {
  name: string;
  type: "string" | "number" | "boolean";
  required: boolean;
  description: string;
}

export interface SubmitJobRequest {
  templateId: string;
  findingId?: string;
  parameters: Record<string, unknown>;
  workspaceMeta?: {
    repo: string;
    branch: string;
  };
}

export interface JobResult {
  jobId: string;
  status: "pending" | "running" | "completed" | "failed";
  exitCode?: number;
  logsPreview?: string;
  artifacts?: Array<{
    name: string;
    ref: string;
  }>;
}

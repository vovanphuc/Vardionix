export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info",
}

export enum FindingStatus {
  OPEN = "open",
  DISMISSED = "dismissed",
  REVIEWED = "reviewed",
  FIXED = "fixed",
}

export enum ScanScope {
  FILE = "file",
  DIR = "dir",
  STAGED = "staged",
  WORKSPACE = "workspace",
}

export enum JobStatus {
  PENDING = "pending",
  RUNNING = "running",
  COMPLETED = "completed",
  FAILED = "failed",
}

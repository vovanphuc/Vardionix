export interface PolicyFile {
  policies: PolicyEntry[];
}

export interface PolicyEntry {
  id: string;
  title: string;
  description: string;
  category: string;
  severity_override?: string;
  rule_patterns: string[];
  remediation_guidance: string;
  references?: string[];
}

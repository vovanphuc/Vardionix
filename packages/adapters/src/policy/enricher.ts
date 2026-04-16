import type { ActiveFinding } from "@vardionix/schemas";
import type { PolicyLocalStore } from "./local-store.js";

export interface EnrichedFinding extends ActiveFinding {
  policyId: string | null;
  policyTitle: string | null;
  policySeverityOverride: ActiveFinding["severity"] | null;
  remediationGuidance: string | null;
}

export class PolicyEnricher {
  constructor(private policyStore: PolicyLocalStore) {}

  enrichFinding(finding: ActiveFinding): EnrichedFinding {
    const policies = this.policyStore.findPoliciesForRule(finding.ruleId);

    if (policies.length === 0) {
      return finding as EnrichedFinding;
    }

    // Use the first matching policy (most specific)
    const policy = policies[0];

    return {
      ...finding,
      policyId: policy.id,
      policyTitle: policy.title,
      policySeverityOverride: policy.severityOverride ?? null,
      remediationGuidance: policy.remediationGuidance,
    };
  }

  enrichFindings(findings: ActiveFinding[]): EnrichedFinding[] {
    return findings.map((f) => this.enrichFinding(f));
  }
}

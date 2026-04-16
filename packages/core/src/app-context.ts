import { getDatabase, FindingsStore, ExcludedFindingsStore } from "@vardionix/store";
import { PolicyEnricher, PolicyLocalStore } from "@vardionix/adapters";
import {
  loadConfig,
  resolvePolicyDirectories,
  type VardionixConfig,
} from "./config.js";
import { ScanService } from "./scan-orchestrator.js";
import { ExplainService } from "./explain-service.js";
import { PatchService } from "./patch-service.js";
import { TriageService } from "./triage-service.js";

export interface VardionixAppContext {
  config: VardionixConfig;
  findingsStore: FindingsStore;
  excludedFindingsStore: ExcludedFindingsStore;
  policyStore: PolicyLocalStore;
  policyEnricher: PolicyEnricher;
  scanService: ScanService;
  explainService: ExplainService;
  patchService: PatchService;
  triageService: TriageService;
}

export async function createAppContext(
  config: VardionixConfig = loadConfig(),
): Promise<VardionixAppContext> {
  const db = await getDatabase();
  const findingsStore = new FindingsStore(db);
  const excludedFindingsStore = new ExcludedFindingsStore(db);
  const policyStore = new PolicyLocalStore(resolvePolicyDirectories(config));
  policyStore.load();
  const policyEnricher = new PolicyEnricher(policyStore);

  const scanService = new ScanService(
    config,
    findingsStore,
    excludedFindingsStore,
    policyStore,
    policyEnricher,
  );
  const explainService = new ExplainService(findingsStore, excludedFindingsStore);
  const patchService = new PatchService(findingsStore, excludedFindingsStore);
  const triageService = new TriageService(findingsStore);

  return {
    config,
    findingsStore,
    excludedFindingsStore,
    policyStore,
    policyEnricher,
    scanService,
    explainService,
    patchService,
    triageService,
  };
}

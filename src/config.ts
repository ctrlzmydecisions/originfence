import path from "node:path";

import type { EvaluationInput } from "./types";
import { fileExists } from "./utils";

export interface ResolvedEvaluationConfig {
  policyPath?: string;
  baselinePolicyPath?: string;
  waiverPath?: string;
  maliciousPackagesFilePath?: string;
  cacheDir: string;
}

export async function discoverRepoConfig(input: EvaluationInput): Promise<ResolvedEvaluationConfig> {
  const discoverRepoConfigEnabled = input.discoverRepoConfig !== false;
  const resolvedPolicyPath = input.policyPath ? path.resolve(input.policyPath) : undefined;
  const resolvedBaselinePolicyPath = input.baselinePolicyPath ? path.resolve(input.baselinePolicyPath) : undefined;
  const resolvedMaliciousPackagesFilePath = input.maliciousPackagesFilePath ? path.resolve(input.maliciousPackagesFilePath) : undefined;

  let policyPath = resolvedPolicyPath;

  if (!policyPath && discoverRepoConfigEnabled) {
    const discoveredPolicyPath = path.join(path.resolve(input.headPath), ".originfence", "policy.yaml");
    if (await fileExists(discoveredPolicyPath)) {
      policyPath = discoveredPolicyPath;
    }
  }

  const cacheDir = path.resolve(input.cacheDir ?? path.join(path.resolve(input.headPath), ".originfence", "cache"));

  return {
    policyPath,
    baselinePolicyPath: resolvedBaselinePolicyPath,
    waiverPath: input.waiverPath ? path.resolve(input.waiverPath) : undefined,
    maliciousPackagesFilePath: resolvedMaliciousPackagesFilePath,
    cacheDir
  };
}

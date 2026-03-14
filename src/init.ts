import path from "node:path";

import { listPolicyPresetNames, renderPolicyPreset, renderWaiversTemplate, type PolicyPresetName } from "./presets";
import { fileExists, writeTextFile } from "./utils";

export interface InitCommandOptions {
  dir?: string;
  preset?: string;
  force?: boolean;
}

export interface InitCommandResult {
  root: string;
  preset: PolicyPresetName;
  policyPath: string;
  waiversPath: string;
  overwritten: boolean;
}

function assertPreset(value: string | undefined): PolicyPresetName {
  if (!value) {
    return "balanced";
  }

  if (listPolicyPresetNames().includes(value as PolicyPresetName)) {
    return value as PolicyPresetName;
  }

  throw new Error(`Unsupported preset: ${value}. Use one of: ${listPolicyPresetNames().join(", ")}`);
}

export async function initOriginFenceConfig(options: InitCommandOptions): Promise<InitCommandResult> {
  const root = path.resolve(options.dir ?? process.cwd());
  const preset = assertPreset(options.preset);
  const configDir = path.join(root, ".originfence");
  const policyPath = path.join(configDir, "policy.yaml");
  const waiversPath = path.join(configDir, "waivers.yaml");
  const alreadyExists = (await Promise.all([fileExists(policyPath), fileExists(waiversPath)])).some(Boolean);

  if (alreadyExists && options.force !== true) {
    throw new Error("OriginFence config already exists. Re-run with --force to overwrite.");
  }

  await writeTextFile(policyPath, renderPolicyPreset(preset));
  await writeTextFile(waiversPath, renderWaiversTemplate());

  return {
    root,
    preset,
    policyPath,
    waiversPath,
    overwritten: alreadyExists
  };
}

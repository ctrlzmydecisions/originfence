#!/usr/bin/env node

import path from "node:path";

import { parseEnforcementMode } from "./enforcement-mode";
import { evaluate } from "./evaluator";
import { writeEvaluationResultArtifacts } from "./evaluation-output";
import { initOriginFenceConfig } from "./init";
import { listPolicyPresetNames } from "./presets";

interface ParsedArgs {
  command: string;
  flags: Record<string, string | boolean>;
}

function printHelp(): void {
  process.stdout.write(
    [
      "Usage:",
      "  originfence eval --base <path> --head <path> [--policy <file>] [--baseline-policy <file>] [--waivers <file>] [--malicious-packages-file <file>] [--json-out <file>] [--summary-out <file>] [--github-step-summary-out <file>] [--cache-dir <dir>] [--refresh] [--now <iso8601>]",
      "  originfence init [--dir <path>] [--preset <balanced|strict|observe>] [--force]",
      "",
      "Commands:",
      "  eval    Evaluate supported dependency changes between two directories.",
      "  init    Create .originfence/policy.yaml and .originfence/waivers.yaml from a preset.",
      "",
      "Notes:",
      "  If --policy is omitted, OriginFence will look for .originfence/policy.yaml under the head path.",
      "  If --waivers is omitted, OriginFence will look for .originfence/waivers.yaml under the head path.",
      `  Available init presets: ${listPolicyPresetNames().join(", ")}.`
    ].join("\n")
  );
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const flags: Record<string, string | boolean> = {};

  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];

    if (!token) {
      continue;
    }

    if (!token.startsWith("--")) {
      throw new Error(`Unexpected argument: ${token}`);
    }

    const key = token.slice(2);
    const next = rest[index + 1];

    if (!next || next.startsWith("--")) {
      flags[key] = true;
      continue;
    }

    flags[key] = next;
    index += 1;
  }

  return {
    command: command ?? "",
    flags
  };
}

function getRequiredString(flags: Record<string, string | boolean>, name: string): string {
  const value = flags[name];

  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Missing required flag --${name}`);
  }

  return value;
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));

  if (!parsed.command || parsed.flags.help) {
    printHelp();
    return 0;
  }

  if (parsed.command === "init") {
    const result = await initOriginFenceConfig({
      dir: typeof parsed.flags.dir === "string" ? String(parsed.flags.dir) : undefined,
      preset: typeof parsed.flags.preset === "string" ? String(parsed.flags.preset) : undefined,
      force: Boolean(parsed.flags.force)
    });

    process.stdout.write(
      [
        `Initialized OriginFence config in ${result.root}`,
        `Preset: ${result.preset}`,
        `Policy: ${result.policyPath}`,
        `Waivers: ${result.waiversPath}`
      ].join("\n") + "\n"
    );
    return 0;
  }

  if (parsed.command !== "eval") {
    throw new Error(`Unsupported command: ${parsed.command}`);
  }

  const basePath = path.resolve(getRequiredString(parsed.flags, "base"));
  const headPath = path.resolve(getRequiredString(parsed.flags, "head"));
  const jsonOut = typeof parsed.flags["json-out"] === "string" ? path.resolve(String(parsed.flags["json-out"])) : undefined;
  const summaryOut = typeof parsed.flags["summary-out"] === "string" ? path.resolve(String(parsed.flags["summary-out"])) : undefined;
  const githubStepSummaryOut =
    typeof parsed.flags["github-step-summary-out"] === "string"
      ? path.resolve(String(parsed.flags["github-step-summary-out"]))
      : process.env.GITHUB_STEP_SUMMARY || undefined;
  const result = await evaluate({
    basePath,
    headPath,
    policyPath: typeof parsed.flags.policy === "string" ? path.resolve(String(parsed.flags.policy)) : undefined,
    baselinePolicyPath:
      typeof parsed.flags["baseline-policy"] === "string" ? path.resolve(String(parsed.flags["baseline-policy"])) : undefined,
    waiverPath: typeof parsed.flags.waivers === "string" ? path.resolve(String(parsed.flags.waivers)) : undefined,
    maliciousPackagesFilePath:
      typeof parsed.flags["malicious-packages-file"] === "string"
        ? path.resolve(String(parsed.flags["malicious-packages-file"]))
        : undefined,
    now: typeof parsed.flags.now === "string" ? String(parsed.flags.now) : new Date().toISOString(),
    discoverRepoConfig: parsed.flags["no-discover-repo-config"] ? false : true,
    cacheDir: typeof parsed.flags["cache-dir"] === "string" ? path.resolve(String(parsed.flags["cache-dir"])) : undefined,
    refreshCache: Boolean(parsed.flags.refresh),
    enforcementMode: parseEnforcementMode(typeof parsed.flags["enforcement-mode"] === "string" ? String(parsed.flags["enforcement-mode"]) : undefined)
  });

  await writeEvaluationResultArtifacts(result, {
    jsonOut,
    summaryOut,
    githubStepSummaryOut
  });

  process.stdout.write(`${result.summaryText}\n`);
  return result.report.status === "failure" ? 1 : 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  });

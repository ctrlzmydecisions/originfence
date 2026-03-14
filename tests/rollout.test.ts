import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { evaluate } from "../src/evaluator";
import { renderPolicyPreset, renderWaiversTemplate } from "../src/presets";
import { FIXED_NOW, makeTempDir, writeFiles } from "./helpers";

test("observe mode keeps findings visible while remapping workflow status to success", async () => {
  const basePath = await makeTempDir("originfence-observe-base-");
  const headPath = await makeTempDir("originfence-observe-head-");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "internal-tooling-lib @ https://packages.example.com/internal-tooling-lib-1.0.0.tar.gz\n"
  });

  const result = await evaluate({
    basePath,
    headPath,
    now: FIXED_NOW,
    enforcementMode: "observe"
  });

  assert.equal(result.report.status, "success");
  assert.equal(result.report.decision, "review");
  assert.equal(result.report.enforcement_mode, "observe");
  assert.match(result.summaryText, /Status: success/);
  assert.match(result.summaryText, /Decision: review/);
  assert.match(result.summaryText, /Enforcement mode: observe/);
  assert.match(result.githubJobSummaryText, /Status: `success`/);
  assert.match(result.githubJobSummaryText, /Decision: `review`/);
});

test("originfence init writes preset-backed config files and requires --force to overwrite", async () => {
  const root = await makeTempDir("originfence-init-");
  const cliPath = path.resolve(process.cwd(), "dist", "src", "cli.js");

  const firstRun = spawnSync(process.execPath, [cliPath, "init", "--dir", root, "--preset", "observe"], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  assert.equal(firstRun.status, 0);
  assert.match(firstRun.stdout, /Preset: observe/);
  assert.equal(await fs.readFile(path.join(root, ".originfence", "policy.yaml"), "utf8"), renderPolicyPreset("observe"));
  assert.equal(await fs.readFile(path.join(root, ".originfence", "waivers.yaml"), "utf8"), renderWaiversTemplate());

  const secondRun = spawnSync(process.execPath, [cliPath, "init", "--dir", root, "--preset", "strict"], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  assert.equal(secondRun.status, 2);
  assert.match(secondRun.stderr, /already exists/);

  const forceRun = spawnSync(process.execPath, [cliPath, "init", "--dir", root, "--preset", "strict", "--force"], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  assert.equal(forceRun.status, 0);
  assert.match(forceRun.stdout, /Preset: strict/);
  assert.equal(await fs.readFile(path.join(root, ".originfence", "policy.yaml"), "utf8"), renderPolicyPreset("strict"));
});

test("published preset files stay aligned with the generated presets", async () => {
  const presetRoot = path.resolve(process.cwd(), "presets");

  assert.equal(await fs.readFile(path.join(presetRoot, "balanced.policy.yaml"), "utf8"), renderPolicyPreset("balanced"));
  assert.equal(await fs.readFile(path.join(presetRoot, "strict.policy.yaml"), "utf8"), renderPolicyPreset("strict"));
  assert.equal(await fs.readFile(path.join(presetRoot, "observe.policy.yaml"), "utf8"), renderPolicyPreset("observe"));
  assert.equal(await fs.readFile(path.join(presetRoot, "waivers.yaml"), "utf8"), renderWaiversTemplate());
});

test("cli rejects unsupported enforcement modes", async () => {
  const basePath = await makeTempDir("originfence-invalid-enforcement-base-");
  const headPath = await makeTempDir("originfence-invalid-enforcement-head-");
  const cliPath = path.resolve(process.cwd(), "dist", "src", "cli.js");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "# no dependencies\n"
  });

  const result = spawnSync(process.execPath, [cliPath, "eval", "--base", basePath, "--head", headPath, "--enforcement-mode", "shadow"], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unsupported enforcement mode/);
});

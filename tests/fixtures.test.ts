import assert from "node:assert/strict";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { evaluate } from "../src/evaluator";
import type { DecisionReport } from "../src/types";
import { FIXED_NOW, fileExists, listFixtureCases, loadFixtureMetadataFetcher, readJsonFile, readTextFile } from "./helpers";

function expectedExitCode(report: DecisionReport): number {
  return report.status === "failure" ? 1 : 0;
}

function normalizeFixtureReportPaths(report: DecisionReport): DecisionReport {
  const normalizePath = (value: string): string => {
    const parent = path.basename(path.dirname(value));
    return path.posix.join(parent, path.basename(value));
  };

  return {
    ...report,
    paths: {
      base: normalizePath(report.paths.base),
      head: normalizePath(report.paths.head)
    }
  };
}

test("fixture cases replay through the CLI", async () => {
  const cliPath = path.resolve(process.cwd(), "dist", "src", "cli.js");
  const cases = await listFixtureCases();

  for (const fixtureCase of cases) {
    const hasEvidenceFixture = await fileExists(path.join(fixtureCase.path, "evidence.json"));

    if (hasEvidenceFixture) {
      continue;
    }

    const args = [
      cliPath,
      "eval",
      "--base",
      path.join(fixtureCase.path, "base"),
      "--head",
      path.join(fixtureCase.path, "head"),
      "--now",
      FIXED_NOW
    ];

    for (const [flag, fileName] of [
      ["--policy", "policy.yaml"],
      ["--waivers", "waivers.yaml"],
      ["--malicious-packages-file", "malicious-packages.json"]
    ] as const) {
      const filePath = path.join(fixtureCase.path, fileName);
      try {
        await readTextFile(filePath);
        args.push(flag, filePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
    }

    const result = spawnSync(process.execPath, args, {
      cwd: process.cwd(),
      encoding: "utf8"
    });

    const expectedReport = await readJsonFile<DecisionReport>(path.join(fixtureCase.path, "expected", "report.json"));
    const expectedSummary = await readTextFile(path.join(fixtureCase.path, "expected", "summary.txt"));

    assert.equal(result.status, expectedExitCode(expectedReport), fixtureCase.name);
    assert.equal(result.stdout, expectedSummary, fixtureCase.name);
  }
});

test("fixture cases replay through the evaluator API", async () => {
  const cases = await listFixtureCases();

  for (const fixtureCase of cases) {
    const input = {
      basePath: path.join(fixtureCase.path, "base"),
      headPath: path.join(fixtureCase.path, "head"),
      now: FIXED_NOW
    };

    const metadataFetcher = await loadFixtureMetadataFetcher(fixtureCase.path);

    if (metadataFetcher) {
      Object.assign(input, { metadataFetcher });
    }

    for (const [property, fileName] of [
      ["policyPath", "policy.yaml"],
      ["waiverPath", "waivers.yaml"],
      ["maliciousPackagesFilePath", "malicious-packages.json"]
    ] as const) {
      const filePath = path.join(fixtureCase.path, fileName);

      try {
        await readTextFile(filePath);
        Object.assign(input, { [property]: filePath });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
    }

    const result = await evaluate(input);

    const expectedReport = await readJsonFile<DecisionReport>(path.join(fixtureCase.path, "expected", "report.json"));
    const expectedSummary = await readTextFile(path.join(fixtureCase.path, "expected", "summary.txt"));

    assert.deepEqual(normalizeFixtureReportPaths(result.report), normalizeFixtureReportPaths(expectedReport), fixtureCase.name);
    assert.equal(`${result.summaryText}\n`, expectedSummary, fixtureCase.name);
  }
});

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import YAML from "yaml";

import reasonCodes from "../schemas/reason-codes.v1.json";
import { assertValidCacheRecord, assertValidDecisionReport, assertValidDriftSnapshot, assertValidPolicy, assertValidWaivers } from "../src/schema";
import type { DecisionReport } from "../src/types";
import { FIXTURES_ROOT, listFixtureCases, readJsonFile } from "./helpers";

test("schema examples validate", async () => {
  const cacheRecord = await readJsonFile(path.join(FIXTURES_ROOT, "examples", "cache-record.json"));
  const driftSnapshot = await readJsonFile(path.join(FIXTURES_ROOT, "examples", "drift-snapshot.json"));

  assert.doesNotThrow(() => assertValidCacheRecord(cacheRecord));
  assert.doesNotThrow(() => assertValidDriftSnapshot(driftSnapshot));
});

test("fixture policies, waivers, and reports validate", async () => {
  const cases = await listFixtureCases();

  for (const fixtureCase of cases) {
    const policyPath = path.join(fixtureCase.path, "policy.yaml");
    const waiversPath = path.join(fixtureCase.path, "waivers.yaml");
    const reportPath = path.join(fixtureCase.path, "expected", "report.json");

    try {
      const policyContent = await fs.readFile(policyPath, "utf8");
      assert.doesNotThrow(() => assertValidPolicy(YAML.parse(policyContent)), fixtureCase.name);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }

    try {
      const waiverContent = await fs.readFile(waiversPath, "utf8");
      assert.doesNotThrow(() => assertValidWaivers(YAML.parse(waiverContent)), fixtureCase.name);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }

    const report = await readJsonFile(reportPath);
    assert.doesNotThrow(() => assertValidDecisionReport(report), fixtureCase.name);
  }
});

test("every reason code appears in at least one fixture report", async () => {
  const expectedReasonCodes = new Set(reasonCodes.map((entry) => entry.code));
  const seenReasonCodes = new Set<string>();
  const cases = await listFixtureCases();

  for (const fixtureCase of cases) {
    const report = await readJsonFile<DecisionReport>(path.join(fixtureCase.path, "expected", "report.json"));

    for (const result of report.results) {
      for (const reason of result.reasons) {
        seenReasonCodes.add(reason.code);
      }
    }
  }

  assert.deepEqual([...seenReasonCodes].sort(), [...expectedReasonCodes].sort());
});

test("fixture reports cover every workflow status path", async () => {
  const statuses = new Set<string>();
  const cases = await listFixtureCases();

  for (const fixtureCase of cases) {
    const report = await readJsonFile<DecisionReport>(path.join(fixtureCase.path, "expected", "report.json"));
    statuses.add(report.status);
  }

  assert.deepEqual([...statuses].sort(), ["failure", "neutral", "success"]);
});

test("workflow status semantics stay consistent with documented mapping", async () => {
  const cases = await listFixtureCases();

  for (const fixtureCase of cases) {
    const report = await readJsonFile<DecisionReport>(path.join(fixtureCase.path, "expected", "report.json"));
    const hasBlockingDecision = report.results.some((result) => result.effective_decision === "block" || result.effective_decision === "review");

    if (report.results.length === 0) {
      assert.equal(report.status, "neutral", fixtureCase.name);
      continue;
    }

    if (hasBlockingDecision) {
      assert.equal(report.status, "failure", fixtureCase.name);
      continue;
    }

    assert.equal(report.status, "success", fixtureCase.name);
  }
});

import Ajv from "ajv/dist/2020";
import addFormats from "ajv-formats";

import cacheRecordSchema from "../schemas/cache-record.schema.json";
import decisionReportSchema from "../schemas/decision-report.schema.json";
import driftSnapshotSchema from "../schemas/drift-snapshot.schema.json";
import policySchema from "../schemas/policy.schema.json";
import waiversSchema from "../schemas/waivers.schema.json";
import type { CacheRecord, DecisionReport, DriftSnapshot, Policy, WaiversFile } from "./types";

const ajv = new Ajv({
  allErrors: true,
  strict: true
});

addFormats(ajv);

const validateDecisionReport = ajv.compile<DecisionReport>(decisionReportSchema);
const validatePolicy = ajv.compile<Policy>(policySchema);
const validateWaivers = ajv.compile<WaiversFile>(waiversSchema);
const validateCacheRecord = ajv.compile<CacheRecord>(cacheRecordSchema);
const validateDriftSnapshot = ajv.compile<DriftSnapshot>(driftSnapshotSchema);

function renderErrors(errors: typeof ajv.errors): string {
  return (errors ?? [])
    .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
    .join("; ");
}

export function assertValidDecisionReport(report: unknown): DecisionReport {
  if (!validateDecisionReport(report)) {
    throw new Error(`Decision report schema validation failed: ${renderErrors(validateDecisionReport.errors)}`);
  }

  return report;
}

export function assertValidPolicy(policy: unknown): Policy {
  if (!validatePolicy(policy)) {
    throw new Error(`Policy schema validation failed: ${renderErrors(validatePolicy.errors)}`);
  }

  return policy;
}

export function assertValidWaivers(waivers: unknown): WaiversFile {
  if (!validateWaivers(waivers)) {
    throw new Error(`Waivers schema validation failed: ${renderErrors(validateWaivers.errors)}`);
  }

  return waivers;
}

export function assertValidCacheRecord(record: unknown): CacheRecord {
  if (!validateCacheRecord(record)) {
    throw new Error(`Cache record schema validation failed: ${renderErrors(validateCacheRecord.errors)}`);
  }

  return record;
}

export function assertValidDriftSnapshot(snapshot: unknown): DriftSnapshot {
  if (!validateDriftSnapshot(snapshot)) {
    throw new Error(`Drift snapshot schema validation failed: ${renderErrors(validateDriftSnapshot.errors)}`);
  }

  return snapshot;
}

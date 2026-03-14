import fs from "node:fs/promises";
import path from "node:path";

import { assertValidCacheRecord, assertValidDriftSnapshot } from "./schema";
import type { CacheRecord, DiagnosticEntry, DriftSnapshot, Ecosystem } from "./types";
import { fileExists, sha256 } from "./utils";

interface CacheEnvelope<T> {
  record: CacheRecord;
  payload: T;
}

export interface CachePolicy {
  freshnessMs: number;
  maxStaleMs: number;
  freshnessTarget: string;
  signalClass: CacheRecord["signal_class"];
}

export interface CachedFetchResult<T> {
  payload: T | null;
  stale: boolean;
  sourceAvailable: boolean;
  freshCacheForSignal: boolean;
  diagnostics: DiagnosticEntry[];
  fetchedAt?: string;
}

function cachePathFor(cacheDir: string, sourceIdentifier: string, lookupKey: string): string {
  const digest = sha256(`${sourceIdentifier}:${lookupKey}`);
  return path.join(cacheDir, "http", sourceIdentifier, `${digest}.json`);
}

function driftPathFor(cacheDir: string, ecosystem: Ecosystem, packageName: string): string {
  return path.join(cacheDir, "drift", ecosystem, `${sha256(packageName)}.json`);
}

async function readCacheEnvelope<T>(cacheDir: string, sourceIdentifier: string, lookupKey: string): Promise<CacheEnvelope<T> | null> {
  const filePath = cachePathFor(cacheDir, sourceIdentifier, lookupKey);

  if (!await fileExists(filePath)) {
    return null;
  }

  const payload = JSON.parse(await fs.readFile(filePath, "utf8")) as CacheEnvelope<T>;
  return {
    record: assertValidCacheRecord(payload.record),
    payload: payload.payload
  };
}

async function writeCacheEnvelope<T>(
  cacheDir: string,
  sourceIdentifier: string,
  lookupKey: string,
  record: CacheRecord,
  payload: T
): Promise<void> {
  const filePath = cachePathFor(cacheDir, sourceIdentifier, lookupKey);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify({ record: assertValidCacheRecord(record), payload }, null, 2), "utf8");
}

function ageMs(fetchedAt: string, now: string): number {
  return Math.max(0, Date.parse(now) - Date.parse(fetchedAt));
}

function buildRecord(
  sourceIdentifier: string,
  lookupKey: string,
  policy: CachePolicy,
  now: string,
  response: Response
): CacheRecord {
  return {
    schema_version: "1",
    source_identifier: sourceIdentifier,
    lookup_key: lookupKey,
    fetched_at: now,
    freshness_target: policy.freshnessTarget,
    etag: response.headers.get("etag") ?? undefined,
    last_modified: response.headers.get("last-modified") ?? undefined,
    serial: response.headers.get("x-pypi-last-serial") ?? undefined,
    signal_class: policy.signalClass
  };
}

interface FetchWithCacheInput {
  cacheDir: string;
  sourceIdentifier: string;
  lookupKey: string;
  url: string;
  now: string;
  policy: CachePolicy;
  refresh?: boolean;
  acceptStatuses?: number[];
  subjectRef?: string;
  method?: string;
  body?: string;
  requestHeaders?: Record<string, string>;
}

async function fetchWithCache<T>(
  input: {
    parser: (response: Response) => Promise<T>;
  } & FetchWithCacheInput
): Promise<CachedFetchResult<T>> {
  const existing = await readCacheEnvelope<T>(input.cacheDir, input.sourceIdentifier, input.lookupKey);
  const diagnostics: DiagnosticEntry[] = [];
  const cacheAge = existing ? ageMs(existing.record.fetched_at, input.now) : Number.POSITIVE_INFINITY;

  if (existing && !input.refresh && cacheAge <= input.policy.freshnessMs) {
    diagnostics.push({
      level: "info",
      source: input.sourceIdentifier,
      code: "CACHE_HIT",
      message: `${input.sourceIdentifier} served ${input.lookupKey} from cache.`,
      subject_ref: input.subjectRef
    });

    return {
      payload: existing.payload,
      stale: false,
      sourceAvailable: true,
      freshCacheForSignal: true,
      diagnostics,
      fetchedAt: existing.record.fetched_at
    };
  }

  const headers: Record<string, string> = {
    ...(input.requestHeaders ?? {})
  };
  const supportsConditionalRevalidation = !input.method || input.method.toUpperCase() === "GET";

  if (supportsConditionalRevalidation && existing?.record.etag) {
    headers["if-none-match"] = existing.record.etag;
  }

  if (supportsConditionalRevalidation && existing?.record.last_modified) {
    headers["if-modified-since"] = existing.record.last_modified;
  }

  try {
    const response = await fetch(input.url, {
      method: input.method,
      headers,
      body: input.body
    });
    const acceptStatuses = new Set(input.acceptStatuses ?? [200]);

    if (response.status === 304 && existing) {
      const refreshedRecord: CacheRecord = {
        ...existing.record,
        fetched_at: input.now,
        etag: response.headers.get("etag") ?? existing.record.etag,
        last_modified: response.headers.get("last-modified") ?? existing.record.last_modified,
        serial: response.headers.get("x-pypi-last-serial") ?? existing.record.serial
      };

      await writeCacheEnvelope(input.cacheDir, input.sourceIdentifier, input.lookupKey, refreshedRecord, existing.payload);
      diagnostics.push({
        level: "info",
        source: input.sourceIdentifier,
        code: "CACHE_REVALIDATED",
        message: `${input.sourceIdentifier} revalidated ${input.lookupKey} with a conditional request.`,
        subject_ref: input.subjectRef
      });

      return {
        payload: existing.payload,
        stale: false,
        sourceAvailable: true,
        freshCacheForSignal: true,
        diagnostics,
        fetchedAt: input.now
      };
    }

    if (!acceptStatuses.has(response.status)) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = response.status === 200 ? await input.parser(response) : null;
    await writeCacheEnvelope(
      input.cacheDir,
      input.sourceIdentifier,
      input.lookupKey,
      buildRecord(input.sourceIdentifier, input.lookupKey, input.policy, input.now, response),
      payload
    );

    return {
      payload,
      stale: false,
      sourceAvailable: true,
      freshCacheForSignal: true,
      diagnostics,
      fetchedAt: input.now
    };
  } catch (error) {
    if (existing && cacheAge <= input.policy.maxStaleMs) {
      diagnostics.push({
        level: "warn",
        source: input.sourceIdentifier,
        code: "STALE_CACHE_FALLBACK",
        message: `${input.sourceIdentifier} fell back to stale cached data for ${input.lookupKey}: ${error instanceof Error ? error.message : String(error)}`,
        subject_ref: input.subjectRef
      });

      return {
        payload: existing.payload,
        stale: true,
        sourceAvailable: false,
        freshCacheForSignal: true,
        diagnostics,
        fetchedAt: existing.record.fetched_at
      };
    }

    diagnostics.push({
      level: "error",
      source: input.sourceIdentifier,
      code: "SOURCE_UNAVAILABLE",
      message: `${input.sourceIdentifier} could not fetch ${input.lookupKey}: ${error instanceof Error ? error.message : String(error)}`,
      subject_ref: input.subjectRef
    });

    return {
      payload: null,
      stale: false,
      sourceAvailable: false,
      freshCacheForSignal: false,
      diagnostics
    };
  }
}

export async function fetchJsonWithCache<T>(input: FetchWithCacheInput): Promise<CachedFetchResult<T>> {
  return fetchWithCache<T>({
    ...input,
    parser: async (response) => (await response.json()) as T
  });
}

export async function fetchTextWithCache(input: FetchWithCacheInput): Promise<CachedFetchResult<string>> {
  return fetchWithCache<string>({
    ...input,
    parser: async (response) => await response.text()
  });
}

export async function readDriftSnapshot(cacheDir: string, ecosystem: Ecosystem, packageName: string): Promise<DriftSnapshot | null> {
  const filePath = driftPathFor(cacheDir, ecosystem, packageName);

  if (!await fileExists(filePath)) {
    return null;
  }

  const payload = JSON.parse(await fs.readFile(filePath, "utf8")) as DriftSnapshot;
  return assertValidDriftSnapshot(payload);
}

export async function writeDriftSnapshot(cacheDir: string, snapshot: DriftSnapshot): Promise<void> {
  const filePath = driftPathFor(cacheDir, snapshot.ecosystem, snapshot.package);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(assertValidDriftSnapshot(snapshot), null, 2), "utf8");
}

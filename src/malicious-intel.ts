import fs from "node:fs/promises";

import { fetchJsonWithCache } from "./cache";
import type {
  Ecosystem,
  DiagnosticEntry,
  MaliciousFeedLookup,
  MaliciousPackageFeed,
  ResolvedDependency,
  SubjectEvidence
} from "./types";

interface LocalOverrideEntry {
  ecosystem: Ecosystem;
  name: string;
  version?: string | null;
  ref?: string;
}

interface OsvQueryResponse {
  vulns?: Array<{
    id?: string;
    affected?: Array<{
      package?: {
        ecosystem?: string;
        name?: string;
      };
      versions?: string[];
      database_specific?: {
        source?: string;
      };
    }>;
    database_specific?: {
      "malicious-packages-origins"?: Array<{
        id?: string;
        source?: string;
      }>;
    };
  }>;
}

interface GitHubGlobalAdvisory {
  ghsa_id?: string;
  html_url?: string;
  vulnerabilities?: Array<{
    package?: {
      ecosystem?: string;
      name?: string;
    };
  }>;
}

interface LookupContext {
  now: string;
  skipRemote?: boolean;
}

interface SourceLookup {
  match?: SubjectEvidence["malicious"];
  diagnostics: DiagnosticEntry[];
  requiredSourceAvailable: boolean;
  freshCacheForSignal: boolean;
}

interface FeedConfig {
  cacheDir: string;
  refreshCache: boolean;
  localOverrideEntries: LocalOverrideEntry[];
}

const MALICIOUS_FEED_CACHE_POLICY = {
  freshnessMs: 60 * 60 * 1000,
  maxStaleMs: 24 * 60 * 60 * 1000,
  freshnessTarget: "1h",
  signalClass: "hard" as const
};

function githubApiHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN ?? process.env.INPUT_GITHUB_TOKEN;

  return {
    accept: "application/vnd.github+json",
    "user-agent": "originfence",
    "x-github-api-version": "2022-11-28",
    ...(token ? { authorization: `Bearer ${token}` } : {})
  };
}

function localOverrideLookup(entries: LocalOverrideEntry[], subject: ResolvedDependency): SourceLookup {
  const match = entries.find((entry) => {
    if (entry.ecosystem !== subject.ecosystem || entry.name !== subject.name) {
      return false;
    }

    if (typeof entry.version === "undefined" || entry.version === null) {
      return true;
    }

    return entry.version === subject.version;
  });

  if (!match) {
    return {
      diagnostics: [],
      requiredSourceAvailable: true,
      freshCacheForSignal: false
    };
  }

  return {
    match: {
      matched: true,
      ref: match.ref ?? `local_override:${match.ecosystem}:${match.name}@${match.version ?? "*"}`
    },
    diagnostics: [],
    requiredSourceAvailable: true,
    freshCacheForSignal: true
  };
}

function osvEcosystem(subject: ResolvedDependency): string | null {
  if (subject.ecosystem === "npm") {
    return "npm";
  }

  if (subject.ecosystem === "pypi") {
    return "PyPI";
  }

  return null;
}

function isRegistryVersionedSubject(subject: ResolvedDependency): boolean {
  return subject.source_type === "registry" && typeof subject.version === "string" && subject.version.length > 0;
}

async function lookupOpenSsfMalicious(subject: ResolvedDependency, config: FeedConfig, context: LookupContext): Promise<SourceLookup> {
  const ecosystem = osvEcosystem(subject);

  if (!ecosystem || !isRegistryVersionedSubject(subject)) {
    return {
      diagnostics: [],
      requiredSourceAvailable: true,
      freshCacheForSignal: false
    };
  }

  const body = JSON.stringify({
    version: subject.version,
    package: {
      name: subject.name,
      ecosystem
    }
  });

  const result = await fetchJsonWithCache<OsvQueryResponse>({
    cacheDir: config.cacheDir,
    sourceIdentifier: "openssf_malicious_osv_query",
    lookupKey: `${subject.ecosystem}:${subject.name}@${subject.version}`,
    url: "https://api.osv.dev/v1/query",
    now: context.now,
    policy: MALICIOUS_FEED_CACHE_POLICY,
    refresh: config.refreshCache,
    subjectRef: `${subject.ecosystem}:${subject.name}@${subject.version}`,
    method: "POST",
    body,
    requestHeaders: {
      "content-type": "application/json"
    }
  });

  const advisory = (result.payload?.vulns ?? []).find((entry) =>
    Boolean(entry.id?.startsWith("MAL-") || entry.database_specific?.["malicious-packages-origins"]?.length)
  );

  return {
    match: advisory
      ? {
          matched: true,
          ref:
            advisory.affected?.[0]?.database_specific?.source ??
            advisory.database_specific?.["malicious-packages-origins"]?.[0]?.id ??
            advisory.id ??
            `openssf:${subject.name}@${subject.version}`
        }
      : undefined,
    diagnostics: result.diagnostics,
    requiredSourceAvailable: result.sourceAvailable,
    freshCacheForSignal: result.freshCacheForSignal
  };
}

async function lookupGitHubNpmMalware(subject: ResolvedDependency, config: FeedConfig, context: LookupContext): Promise<SourceLookup> {
  if (subject.ecosystem !== "npm" || !isRegistryVersionedSubject(subject)) {
    return {
      diagnostics: [],
      requiredSourceAvailable: true,
      freshCacheForSignal: false
    };
  }

  const affects = encodeURIComponent(`${subject.name}@${subject.version}`);
  const result = await fetchJsonWithCache<GitHubGlobalAdvisory[]>({
    cacheDir: config.cacheDir,
    sourceIdentifier: "github_npm_malware_advisories",
    lookupKey: `${subject.name}@${subject.version}`,
    url: `https://api.github.com/advisories?type=malware&ecosystem=npm&affects=${affects}&per_page=100`,
    now: context.now,
    policy: MALICIOUS_FEED_CACHE_POLICY,
    refresh: config.refreshCache,
    subjectRef: `${subject.ecosystem}:${subject.name}@${subject.version}`,
    requestHeaders: githubApiHeaders()
  });

  const advisory = (result.payload ?? []).find((entry) =>
    entry.vulnerabilities?.some((vulnerability) => vulnerability.package?.ecosystem === "npm" && vulnerability.package?.name === subject.name)
  );

  const diagnostics = result.sourceAvailable
    ? result.diagnostics
    : result.diagnostics.map((entry) => ({
        ...entry,
        level: entry.level === "error" ? "warn" : entry.level,
        code: entry.code === "SOURCE_UNAVAILABLE" ? "SUPPLEMENTAL_SOURCE_UNAVAILABLE" : entry.code,
        message: `Supplemental GitHub npm malware advisories were unavailable: ${entry.message}`
      }));

  return {
    match: advisory
      ? {
          matched: true,
          ref: advisory.html_url ?? advisory.ghsa_id ?? `github:${subject.name}@${subject.version}`
        }
      : undefined,
    diagnostics,
    requiredSourceAvailable: true,
    freshCacheForSignal: result.freshCacheForSignal
  };
}

class CombinedMaliciousPackageFeed implements MaliciousPackageFeed {
  private readonly config: FeedConfig;

  public constructor(config: FeedConfig) {
    this.config = config;
  }

  public async lookup(subject: ResolvedDependency, options: { now: string; skipRemote?: boolean }): Promise<MaliciousFeedLookup> {
    const localResult = localOverrideLookup(this.config.localOverrideEntries, subject);

    if (localResult.match) {
      return {
        malicious: localResult.match,
        diagnostics: localResult.diagnostics,
        sourceAvailable: true,
        freshCacheForSignal: true
      };
    }

    if (options.skipRemote) {
      return {
        diagnostics: [],
        sourceAvailable: true,
        freshCacheForSignal: false
      };
    }

    const sources: SourceLookup[] = [];

    const openSsfResult = await lookupOpenSsfMalicious(subject, this.config, { now: options.now });
    sources.push(openSsfResult);
    if (openSsfResult.match) {
      return {
        malicious: openSsfResult.match,
        diagnostics: openSsfResult.diagnostics,
        sourceAvailable: openSsfResult.requiredSourceAvailable,
        freshCacheForSignal: openSsfResult.freshCacheForSignal
      };
    }

    const githubResult = await lookupGitHubNpmMalware(subject, this.config, { now: options.now });
    sources.push(githubResult);
    if (githubResult.match) {
      return {
        malicious: githubResult.match,
        diagnostics: [...openSsfResult.diagnostics, ...githubResult.diagnostics],
        sourceAvailable: openSsfResult.requiredSourceAvailable,
        freshCacheForSignal: openSsfResult.freshCacheForSignal || githubResult.freshCacheForSignal
      };
    }

    return {
      diagnostics: sources.flatMap((source) => source.diagnostics),
      sourceAvailable: sources.every((source) => source.requiredSourceAvailable),
      freshCacheForSignal: sources.some((source) => source.freshCacheForSignal)
    };
  }
}

async function loadLocalOverrideEntries(filePath?: string): Promise<LocalOverrideEntry[]> {
  if (!filePath) {
    return [];
  }

  const content = await fs.readFile(filePath, "utf8");
  return JSON.parse(content) as LocalOverrideEntry[];
}

export async function loadMaliciousPackageFeed(input: {
  cacheDir: string;
  refreshCache: boolean;
  localOverrideFilePath?: string;
}): Promise<MaliciousPackageFeed> {
  return new CombinedMaliciousPackageFeed({
    cacheDir: input.cacheDir,
    refreshCache: input.refreshCache,
    localOverrideEntries: await loadLocalOverrideEntries(input.localOverrideFilePath)
  });
}

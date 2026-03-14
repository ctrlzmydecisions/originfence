import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { loadMaliciousPackageFeed } from "../src/malicious-intel";
import type { ResolvedDependency } from "../src/types";
import { makeTempDir } from "./helpers";

function makeJsonResponse(payload: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {})
    },
    ...init
  });
}

function npmSubject(name: string, version: string): ResolvedDependency {
  return {
    ecosystem: "npm",
    name,
    version,
    source_type: "registry",
    manifest_path: "package.json",
    lockfile_path: "package-lock.json",
    top_level: true,
    registry_host: "registry.npmjs.org"
  };
}

test("local malicious override entries win without network lookups", async () => {
  const cacheDir = await makeTempDir("originfence-malicious-cache-");
  const overridePath = path.join(cacheDir, "malicious-overrides.json");
  const originalFetch = global.fetch;

  await fs.writeFile(
    overridePath,
    JSON.stringify(
      [
        {
          ecosystem: "npm",
          name: "evil-pkg",
          version: "1.4.2",
          ref: "local-override:evil-pkg@1.4.2"
        }
      ],
      null,
      2
    ),
    "utf8"
  );

  try {
    global.fetch = async () => {
      throw new Error("network should not be used for local override matches");
    };

    const feed = await loadMaliciousPackageFeed({
      cacheDir,
      refreshCache: false,
      localOverrideFilePath: overridePath
    });

    const result = await feed.lookup(npmSubject("evil-pkg", "1.4.2"), {
      now: "2026-03-14T13:30:00Z"
    });

    assert.equal(result.malicious?.matched, true);
    assert.equal(result.malicious?.ref, "local-override:evil-pkg@1.4.2");
    assert.equal(result.sourceAvailable, true);
  } finally {
    global.fetch = originalFetch;
  }
});

test("OpenSSF malicious-packages via OSV is the primary malicious feed", async () => {
  const cacheDir = await makeTempDir("originfence-openssf-cache-");
  const originalFetch = global.fetch;

  try {
    global.fetch = async (input) => {
      const url = String(input);

      if (url === "https://api.osv.dev/v1/query") {
        return makeJsonResponse({
          vulns: [
            {
              id: "MAL-2025-9999",
              affected: [
                {
                  package: {
                    ecosystem: "npm",
                    name: "evil-pkg"
                  },
                  database_specific: {
                    source: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/evil-pkg/MAL-2025-9999.json"
                  }
                }
              ],
              database_specific: {
                "malicious-packages-origins": [
                  {
                    source: "ghsa-malware",
                    id: "GHSA-test-test-test"
                  }
                ]
              }
            }
          ]
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    const feed = await loadMaliciousPackageFeed({
      cacheDir,
      refreshCache: false
    });

    const result = await feed.lookup(npmSubject("evil-pkg", "1.4.2"), {
      now: "2026-03-14T13:30:00Z"
    });

    assert.equal(result.malicious?.matched, true);
    assert.match(result.malicious?.ref ?? "", /ossf\/malicious-packages/);
    assert.equal(result.sourceAvailable, true);
  } finally {
    global.fetch = originalFetch;
  }
});

test("GitHub npm malware advisories act as a fallback malicious source", async () => {
  const cacheDir = await makeTempDir("originfence-ghsa-cache-");
  const originalFetch = global.fetch;

  try {
    global.fetch = async (input) => {
      const url = String(input);

      if (url === "https://api.osv.dev/v1/query") {
        return makeJsonResponse({ vulns: [] });
      }

      if (url.includes("https://api.github.com/advisories?type=malware&ecosystem=npm&affects=shadowy-lib%402.1.0")) {
        return makeJsonResponse([
          {
            ghsa_id: "GHSA-r38v-v7pv-rgrj",
            html_url: "https://github.com/advisories/GHSA-r38v-v7pv-rgrj",
            vulnerabilities: [
              {
                package: {
                  ecosystem: "npm",
                  name: "shadowy-lib"
                }
              }
            ]
          }
        ]);
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    const feed = await loadMaliciousPackageFeed({
      cacheDir,
      refreshCache: false
    });

    const result = await feed.lookup(npmSubject("shadowy-lib", "2.1.0"), {
      now: "2026-03-14T13:30:00Z"
    });

    assert.equal(result.malicious?.matched, true);
    assert.equal(result.malicious?.ref, "https://github.com/advisories/GHSA-r38v-v7pv-rgrj");
    assert.equal(result.sourceAvailable, true);
  } finally {
    global.fetch = originalFetch;
  }
});

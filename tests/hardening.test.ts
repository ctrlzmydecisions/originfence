import assert from "node:assert/strict";
import test from "node:test";

import { evaluate } from "../src/evaluator";
import { setSigstoreVerifierForTests } from "../src/provenance";
import { makeTempDir, writeFiles } from "./helpers";

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

function maybeMaliciousIntelResponse(url: string): Response | null {
  if (url === "https://api.osv.dev/v1/query") {
    return makeJsonResponse({ vulns: [] });
  }

  if (url.startsWith("https://api.github.com/advisories?type=malware&ecosystem=npm&affects=")) {
    return makeJsonResponse([]);
  }

  return null;
}

test("evaluate uses stale cached registry metadata when the live source is unavailable", async () => {
  const basePath = await makeTempDir("originfence-hardening-base-");
  const headPath = await makeTempDir("originfence-hardening-head-");
  const cacheDir = await makeTempDir("originfence-hardening-cache-");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "young-lib==1.0.0\n"
  });

  const originalFetch = global.fetch;

  try {
    global.fetch = async (input) => {
      const url = String(input);
      const maliciousIntelResponse = maybeMaliciousIntelResponse(url);

      if (maliciousIntelResponse) {
        return maliciousIntelResponse;
      }

      if (url === "https://pypi.org/pypi/young-lib/json") {
        return makeJsonResponse({
          info: {
            project_urls: {
              Source: "https://github.com/example/young-lib"
            }
          },
          ownership: [{ username: "alice" }],
          releases: {
            "1.0.0": [
              {
                filename: "young-lib-1.0.0.tar.gz",
                upload_time_iso_8601: "2026-03-12T12:00:00Z"
              }
            ]
          },
          project_status: {
            status: "active"
          },
          last_serial: 101
        }, {
          headers: {
            etag: "\"young-lib-v1\"",
            "x-pypi-last-serial": "101"
          }
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:00:00Z",
      cacheDir
    });

    global.fetch = async () => {
      throw new Error("simulated outage");
    };

    const result = await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:20:00Z",
      cacheDir
    });

    assert.equal(result.report.status, "success");
    assert.equal(result.report.results[0]?.effective_decision, "warn");
    assert.equal(result.report.results[0]?.evaluation_meta.hard_signal_state, "stale");
    assert.equal(result.report.results[0]?.evidence.some((entry) => entry.stale === true), true);
    assert.equal(result.report.diagnostics?.some((entry) => entry.code === "STALE_CACHE_FALLBACK"), true);
  } finally {
    global.fetch = originalFetch;
  }
});

test("evaluate blocks when a hard-signal source is unavailable and no cache exists", async () => {
  const basePath = await makeTempDir("originfence-no-cache-base-");
  const headPath = await makeTempDir("originfence-no-cache-head-");
  const cacheDir = await makeTempDir("originfence-no-cache-cache-");
  const originalFetch = global.fetch;

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "young-lib==1.0.0\n"
  });

  try {
    global.fetch = async () => {
      throw new Error("simulated outage");
    };

    const result = await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:00:00Z",
      cacheDir
    });

    assert.equal(result.report.status, "failure");
    assert.equal(result.report.results[0]?.reasons.some((reason) => reason.code === "HARD_SIGNAL_SOURCE_UNAVAILABLE"), true);
  } finally {
    global.fetch = originalFetch;
  }
});

test("evaluate emits maintainer drift after a new snapshot is observed", async () => {
  const basePath = await makeTempDir("originfence-drift-base-");
  const headPath = await makeTempDir("originfence-drift-head-");
  const cacheDir = await makeTempDir("originfence-drift-cache-");
  const originalFetch = global.fetch;
  let owners = ["alice"];

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "stable-lib==1.0.0\n"
  });

  try {
    global.fetch = async (input) => {
      const url = String(input);
      const maliciousIntelResponse = maybeMaliciousIntelResponse(url);

      if (maliciousIntelResponse) {
        return maliciousIntelResponse;
      }

      if (url === "https://pypi.org/pypi/stable-lib/json") {
        return makeJsonResponse({
          info: {
            project_urls: {
              Source: "https://github.com/example/stable-lib"
            }
          },
          ownership: owners.map((username) => ({ username })),
          releases: {
            "1.0.0": [
              {
                filename: "stable-lib-1.0.0.tar.gz",
                upload_time_iso_8601: "2025-12-01T00:00:00Z"
              }
            ]
          },
          project_status: {
            status: "active"
          },
          last_serial: owners[0] === "alice" ? 201 : 202
        }, {
          headers: {
            etag: owners[0] === "alice" ? "\"stable-lib-a\"" : "\"stable-lib-b\"",
            "x-pypi-last-serial": owners[0] === "alice" ? "201" : "202"
          }
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:00:00Z",
      cacheDir
    });

    owners = ["bob"];

    const result = await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:20:00Z",
      cacheDir
    });

    assert.equal(result.report.status, "success");
    assert.equal(result.report.results[0]?.reasons.some((reason) => reason.code === "MAINTAINER_SET_CHANGE"), true);
  } finally {
    global.fetch = originalFetch;
  }
});

test("evaluate blocks PyPI quarantined status but does not treat deprecated status as quarantined", async () => {
  const basePath = await makeTempDir("originfence-status-base-");
  const headPath = await makeTempDir("originfence-status-head-");
  const cacheDir = await makeTempDir("originfence-status-cache-");
  const originalFetch = global.fetch;
  let status = "quarantined";

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "status-lib==1.0.0\n"
  });

  try {
    global.fetch = async (input) => {
      const url = String(input);
      const maliciousIntelResponse = maybeMaliciousIntelResponse(url);

      if (maliciousIntelResponse) {
        return maliciousIntelResponse;
      }

      if (url === "https://pypi.org/pypi/status-lib/json") {
        return makeJsonResponse({
          info: {
            project_urls: {
              Source: "https://github.com/example/status-lib"
            }
          },
          ownership: [{ username: "alice" }],
          releases: {
            "1.0.0": [
              {
                filename: "status-lib-1.0.0.tar.gz",
                upload_time_iso_8601: "2026-03-10T00:00:00Z"
              }
            ]
          },
          project_status: {
            status
          },
          last_serial: 501
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    const quarantinedResult = await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:00:00Z",
      cacheDir
    });

    assert.equal(quarantinedResult.report.status, "failure");
    assert.equal(quarantinedResult.report.results[0]?.reasons.some((reason) => reason.code === "REGISTRY_QUARANTINED"), true);

    status = "deprecated";

    const deprecatedResult = await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:20:00Z",
      cacheDir
    });

    assert.equal(deprecatedResult.report.results[0]?.reasons.some((reason) => reason.code === "REGISTRY_QUARANTINED"), false);
  } finally {
    global.fetch = originalFetch;
  }
});

test("evaluate emits publisher drift for npm packages from OriginFence snapshots", async () => {
  const basePath = await makeTempDir("originfence-publisher-base-");
  const headPath = await makeTempDir("originfence-publisher-head-");
  const cacheDir = await makeTempDir("originfence-publisher-cache-");
  const originalFetch = global.fetch;
  let publisher = "alice";

  await writeFiles(basePath, {
    "package.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0"
    }, null, 2),
    "package-lock.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": {
          name: "fixture-app",
          version: "1.0.0"
        }
      }
    }, null, 2)
  });

  await writeFiles(headPath, {
    "package.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      dependencies: {
        "publisher-lib": "^1.0.0"
      }
    }, null, 2),
    "package-lock.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": {
          name: "fixture-app",
          version: "1.0.0",
          dependencies: {
            "publisher-lib": "^1.0.0"
          }
        },
        "node_modules/publisher-lib": {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/publisher-lib/-/publisher-lib-1.0.0.tgz"
        }
      }
    }, null, 2)
  });

  try {
    global.fetch = async (input) => {
      const url = String(input);
      const maliciousIntelResponse = maybeMaliciousIntelResponse(url);

      if (maliciousIntelResponse) {
        return maliciousIntelResponse;
      }

      if (url === "https://registry.npmjs.org/publisher-lib") {
        return makeJsonResponse({
          repository: "https://github.com/example/publisher-lib",
          maintainers: [{ name: "maintainer" }],
          time: {
            "1.0.0": "2025-12-01T00:00:00Z"
          },
          versions: {
            "1.0.0": {
              _npmUser: {
                name: publisher
              },
              repository: "https://github.com/example/publisher-lib"
            }
          }
        }, {
          headers: {
            etag: publisher === "alice" ? "\"publisher-a\"" : "\"publisher-b\""
          }
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:00:00Z",
      cacheDir
    });

    publisher = "bob";

    const result = await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:20:00Z",
      cacheDir
    });

    assert.equal(result.report.status, "failure");
    assert.equal(result.report.results[0]?.reasons.some((reason) => reason.code === "PUBLISHER_IDENTITY_DRIFT"), true);
  } finally {
    global.fetch = originalFetch;
  }
});

test("evaluate accepts structurally valid npm attestations when provenance is required", async () => {
  const basePath = await makeTempDir("originfence-prov-base-");
  const headPath = await makeTempDir("originfence-prov-head-");
  const cacheDir = await makeTempDir("originfence-prov-cache-");
  const originalFetch = global.fetch;
  const originalVerifierReset = () => setSigstoreVerifierForTests(null);

  const statement = Buffer.from(JSON.stringify({
    _type: "https://in-toto.io/Statement/v0.1",
    subject: [
      {
        name: "pkg:npm/trusted-lib@1.0.0",
        digest: {
          sha512: "deadbeef"
        }
      }
    ],
    predicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
    predicate: {
      name: "trusted-lib",
      version: "1.0.0",
      registry: "https://registry.npmjs.org"
    }
  })).toString("base64");

  await writeFiles(basePath, {
    "package.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0"
    }, null, 2),
    "package-lock.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": {
          name: "fixture-app",
          version: "1.0.0"
        }
      }
    }, null, 2)
  });

  await writeFiles(headPath, {
    "package.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      dependencies: {
        "trusted-lib": "^1.0.0"
      }
    }, null, 2),
    "package-lock.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": {
          name: "fixture-app",
          version: "1.0.0",
          dependencies: {
            "trusted-lib": "^1.0.0"
          }
        },
        "node_modules/trusted-lib": {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/trusted-lib/-/trusted-lib-1.0.0.tgz"
        }
      }
    }, null, 2),
    ".originfence/policy.yaml": [
      "version: 1",
      "provenance:",
      "  npm:",
      "    require_for:",
      "      - trusted-*",
      "    missing_action: block"
    ].join("\n")
  });

  try {
    global.fetch = async (input) => {
      const url = String(input);
      const maliciousIntelResponse = maybeMaliciousIntelResponse(url);

      if (maliciousIntelResponse) {
        return maliciousIntelResponse;
      }

      if (url === "https://registry.npmjs.org/trusted-lib") {
        return makeJsonResponse({
          repository: "https://github.com/example/trusted-lib",
          maintainers: [{ name: "maintainer" }],
          time: {
            "1.0.0": "2025-12-01T00:00:00Z"
          },
          versions: {
            "1.0.0": {
              _npmUser: {
                name: "publisher"
              },
              repository: "https://github.com/example/trusted-lib",
              dist: {
                integrity: "sha512-3q2+7w==",
                attestations: {
                  url: "https://registry.npmjs.org/-/npm/v1/attestations/trusted-lib@1.0.0",
                  provenance: {
                    predicateType: "https://slsa.dev/provenance/v1"
                  }
                }
              }
            }
          }
        });
      }

      if (url === "https://registry.npmjs.org/-/npm/v1/attestations/trusted-lib@1.0.0") {
        return makeJsonResponse({
          attestations: [
            {
              predicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
              bundle: {
                mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
                verificationMaterial: {
                  publicKey: {
                    hint: "SHA256:test-registry-key"
                  },
                  tlogEntries: [{}]
                },
                dsseEnvelope: {
                  payloadType: "application/vnd.in-toto+json",
                  signatures: [
                    {
                      sig: "MEUCIQD1JCA8lWR9na44+zY2tr13sEuMCIu+FLS6eDkwESP5KgIgQDNG+eA5PiLSvVd+0AJn3Nk1V3CpRjRoz59L/MMTxyM=",
                      keyid: "SHA256:test-registry-key"
                    }
                  ],
                  payload: statement
                }
              }
            }
          ]
        });
      }

      if (url === "https://registry.npmjs.org/-/npm/v1/keys") {
        return makeJsonResponse({
          keys: [
            {
              keyid: "SHA256:test-registry-key",
              key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g=="
            }
          ]
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };
    setSigstoreVerifierForTests(async () => ({}));

    const result = await evaluate({
      basePath,
      headPath,
      now: "2026-03-13T12:00:00Z",
      cacheDir
    });

    assert.equal(result.report.status, "success");
    assert.equal(result.report.results[0]?.effective_decision, "allow");
    assert.equal(result.report.results[0]?.reasons.length, 0);
  } finally {
    originalVerifierReset();
    global.fetch = originalFetch;
  }
});

test("evaluate handles PyPI ownership objects from the live JSON API shape", async () => {
  const basePath = await makeTempDir("originfence-pypi-ownership-base-");
  const headPath = await makeTempDir("originfence-pypi-ownership-head-");
  const cacheDir = await makeTempDir("originfence-pypi-ownership-cache-");
  const originalFetch = global.fetch;

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "requests==2.32.3\n"
  });

  try {
    global.fetch = async (input) => {
      const url = String(input);
      const maliciousIntelResponse = maybeMaliciousIntelResponse(url);

      if (maliciousIntelResponse) {
        return maliciousIntelResponse;
      }

      if (url === "https://pypi.org/pypi/requests/json") {
        return makeJsonResponse({
          info: {
            project_urls: {
              Source: "https://github.com/psf/requests"
            }
          },
          ownership: {
            organization: null,
            roles: [
              { role: "Owner", user: "Lukasa" },
              { role: "Owner", user: "graffatcolmingov" }
            ]
          },
          releases: {
            "2.32.3": [
              {
                filename: "requests-2.32.3-py3-none-any.whl",
                upload_time_iso_8601: "2024-05-29T00:00:00Z"
              }
            ]
          },
          project_status: {
            status: "active"
          },
          last_serial: 30758180
        }, {
          headers: {
            etag: "\"requests-v1\"",
            "x-pypi-last-serial": "30758180"
          }
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    const result = await evaluate({
      basePath,
      headPath,
      now: "2026-03-14T12:00:00Z",
      cacheDir
    });

    assert.equal(result.report.status, "success");
    assert.equal(result.report.results[0]?.effective_decision, "allow");
  } finally {
    global.fetch = originalFetch;
  }
});

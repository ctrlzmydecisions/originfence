import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { evaluate } from "../src/evaluator";
import { FIXED_NOW, makeTempDir, writeFiles } from "./helpers";

test("evaluate discovers repo-local policy and waiver files and renders waived results explicitly", async () => {
  const basePath = await makeTempDir("originfence-policy-base-");
  const headPath = await makeTempDir("originfence-policy-head-");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "internal-tooling-lib @ git+https://github.com/our-org/internal-tooling-lib.git@9f2e1d4\n",
    ".originfence/policy.yaml": [
      "version: 1",
      "waivers:",
      "  file: .originfence/waivers.yaml"
    ].join("\n"),
    ".originfence/waivers.yaml": [
      "version: 1",
      "waivers:",
      "  - id: OF-2026-0002",
      "    owner: team-platform",
      "    justification: Internal library is still being migrated to the private index",
      "    created_at: 2026-03-10T00:00:00Z",
      "    expires_at: 2026-03-27T00:00:00Z",
      "    reason_codes:",
      "      - VCS_SOURCE",
      "    effect: downgrade_to_warn",
      "    scope:",
      "      ecosystem: pypi",
      "      package: internal-tooling-lib",
      "      version: git+https://github.com/our-org/internal-tooling-lib.git@9f2e1d4"
    ].join("\n")
  });

  const result = await evaluate({
    basePath,
    headPath,
    now: FIXED_NOW
  });

  assert.equal(result.report.status, "success");
  assert.equal(result.report.results[0]?.base_decision, "review");
  assert.equal(result.report.results[0]?.effective_decision, "warn");
  assert.equal(result.report.results[0]?.waived, true);
  assert.equal(result.report.results[0]?.waived_from, "review");
  assert.match(result.summaryText, /waived: OF-2026-0002/);
  assert.equal(path.basename(result.resolvedConfig.policyPath ?? ""), "policy.yaml");
  assert.equal(path.basename(result.resolvedConfig.waiverPath ?? ""), "waivers.yaml");
});

test("baseline policy cannot be weakened by repo policy", async () => {
  const basePath = await makeTempDir("originfence-baseline-base-");
  const headPath = await makeTempDir("originfence-baseline-head-");
  const baselinePolicyPath = path.join(headPath, "..", "baseline-policy.yaml");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "critical-lib==1.0.0\n",
    ".originfence/policy.yaml": [
      "version: 1",
      "provenance:",
      "  pypi:",
      "    require_for:",
      "      - critical-*",
      "    missing_action: review"
    ].join("\n")
  });

  await fs.writeFile(
    baselinePolicyPath,
    [
      "version: 1",
      "provenance:",
      "  pypi:",
      "    require_for:",
      "      - critical-*",
      "    missing_action: block"
    ].join("\n"),
    "utf8"
  );

  const originalFetch = global.fetch;

  try {
    global.fetch = async (input) => {
      const url = String(input);

      if (url === "https://api.osv.dev/v1/query") {
        return new Response(JSON.stringify({ vulns: [] }), {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      if (url === "https://pypi.org/pypi/critical-lib/json") {
        return new Response(
          JSON.stringify({
            info: {
              project_urls: {
                Source: "https://github.com/example/critical-lib"
              }
            },
            ownership: [{ username: "alice" }],
            releases: {
              "1.0.0": [
                {
                  filename: "critical-lib-1.0.0.tar.gz",
                  upload_time_iso_8601: "2025-03-01T00:00:00Z"
                }
              ]
            },
            project_status: {
              status: "active"
            },
            last_serial: 301
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
              etag: "\"critical-lib-v1\"",
              "x-pypi-last-serial": "301"
            }
          }
        );
      }

      if (url === "https://pypi.org/integrity/critical-lib/1.0.0/critical-lib-1.0.0.tar.gz/provenance") {
        return new Response(JSON.stringify({ attestation_bundles: [] }), {
          status: 404,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    const result = await evaluate({
      basePath,
      headPath,
      baselinePolicyPath,
      now: FIXED_NOW
    });

    assert.equal(result.report.results[0]?.effective_decision, "block");
    assert.equal(result.report.status, "failure");
    assert.equal(path.basename(result.resolvedConfig.policyPath ?? ""), "policy.yaml");
  } finally {
    global.fetch = originalFetch;
  }
});

test("cli returns a validation error for malformed policy files", async () => {
  const basePath = await makeTempDir("originfence-invalid-policy-base-");
  const headPath = await makeTempDir("originfence-invalid-policy-head-");
  const cliPath = path.resolve(process.cwd(), "dist", "src", "cli.js");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "internal-tooling-lib @ https://packages.example.com/internal-tooling-lib-1.0.0.tar.gz\n",
    ".originfence/policy.yaml": "version: invalid\n"
  });

  const result = spawnSync(process.execPath, ["dist/src/cli.js", "eval", "--base", basePath, "--head", headPath, "--now", FIXED_NOW], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /Policy schema validation failed/);
  assert.equal(cliPath.endsWith("cli.js"), true);
});

test("cli returns a validation error for malformed waiver files", async () => {
  const basePath = await makeTempDir("originfence-invalid-waiver-base-");
  const headPath = await makeTempDir("originfence-invalid-waiver-head-");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "internal-tooling-lib @ git+https://github.com/our-org/internal-tooling-lib.git@9f2e1d4\n",
    ".originfence/policy.yaml": [
      "version: 1",
      "waivers:",
      "  file: .originfence/waivers.yaml"
    ].join("\n"),
    ".originfence/waivers.yaml": [
      "version: 1",
      "waivers:",
      "  - id: OF-2026-0003",
      "    justification: missing owner on purpose",
      "    created_at: 2026-03-10T00:00:00Z",
      "    expires_at: 2026-03-27T00:00:00Z",
      "    reason_codes:",
      "      - VCS_SOURCE",
      "    effect: downgrade_to_warn",
      "    scope:",
      "      ecosystem: pypi",
      "      package: internal-tooling-lib"
    ].join("\n")
  });

  const result = spawnSync(process.execPath, ["dist/src/cli.js", "eval", "--base", basePath, "--head", headPath, "--now", FIXED_NOW], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /Waivers schema validation failed/);
});

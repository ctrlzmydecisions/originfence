import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { TEST_TMP_ROOT, writeFiles } from "./helpers";

async function makeGitRepo(files: Record<string, string>, secondCommitFiles: Record<string, string>): Promise<{ root: string; baseRev: string }> {
  await fs.mkdir(TEST_TMP_ROOT, { recursive: true });
  const root = await fs.mkdtemp(path.join(TEST_TMP_ROOT, "originfence-gha-"));

  const run = (args: string[]): string => {
    const result = spawnSync("git", args, {
      cwd: root,
      encoding: "utf8"
    });

    if (result.status !== 0) {
      throw new Error(result.stderr.trim() || `git ${args.join(" ")} failed`);
    }

    return result.stdout.trim();
  };

  run(["init"]);
  run(["config", "user.name", "OriginFence Test"]);
  run(["config", "user.email", "originfence@example.com"]);

  await writeFiles(root, files);
  run(["add", "."]);
  run(["commit", "-m", "base"]);
  const baseRev = run(["rev-parse", "HEAD"]);

  await writeFiles(root, secondCommitFiles);
  run(["add", "."]);
  run(["commit", "-m", "head"]);

  return { root, baseRev };
}

async function readGitHubOutputs(filePath: string): Promise<Record<string, string>> {
  const content = await fs.readFile(filePath, "utf8");
  const outputs: Record<string, string> = {};
  const matches = content.matchAll(/^(?<name>[A-Za-z0-9_-]+)<<PTG_EOF\n(?<value>[\s\S]*?)\nPTG_EOF$/gmu);

  for (const match of matches) {
    if (match.groups?.name && typeof match.groups.value === "string") {
      outputs[match.groups.name] = match.groups.value;
    }
  }

  return outputs;
}

test("github action wrapper writes outputs and a markdown summary for failing required checks", async () => {
  const repo = await makeGitRepo(
    {
      "requirements.txt": "# no dependencies\n"
    },
    {
      "requirements.txt": "internal-tooling-lib @ https://packages.example.com/internal-tooling-lib-1.0.0.tar.gz\n"
    }
  );

  const outputFile = path.join(repo.root, "github-output.txt");
  const summaryFile = path.join(repo.root, "github-step-summary.md");

  const result = spawnSync(process.execPath, ["dist/src/github-action.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GITHUB_WORKSPACE: repo.root,
      GITHUB_ACTION_PATH: process.cwd(),
      GITHUB_OUTPUT: outputFile,
      GITHUB_STEP_SUMMARY: summaryFile,
      INPUT_BASE_REV: repo.baseRev
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 1);
  const outputs = await readGitHubOutputs(outputFile);
  const summary = await fs.readFile(summaryFile, "utf8");

  assert.equal(outputs.status, "failure");
  assert.equal(outputs.decision, "review");
  assert.equal(outputs["report-path"], ".originfence/out/report.json");
  assert.equal(outputs["summary-path"], ".originfence/out/summary.txt");
  assert.match(summary, /## OriginFence/);
  assert.match(summary, /Decision: `failure`/);
  assert.match(summary, /### Review Required/);
  assert.match(summary, /DIRECT_URL_SOURCE/);
});

test("github action wrapper supports observe mode without turning the workflow red", async () => {
  const repo = await makeGitRepo(
    {
      "requirements.txt": "# no dependencies\n"
    },
    {
      "requirements.txt": "internal-tooling-lib @ https://packages.example.com/internal-tooling-lib-1.0.0.tar.gz\n"
    }
  );

  const outputFile = path.join(repo.root, "github-output.txt");
  const summaryFile = path.join(repo.root, "github-step-summary.md");

  const result = spawnSync(process.execPath, ["dist/src/github-action.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GITHUB_WORKSPACE: repo.root,
      GITHUB_ACTION_PATH: process.cwd(),
      GITHUB_OUTPUT: outputFile,
      GITHUB_STEP_SUMMARY: summaryFile,
      INPUT_BASE_REV: repo.baseRev,
      INPUT_ENFORCEMENT_MODE: "observe"
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 0);
  const outputs = await readGitHubOutputs(outputFile);
  const summary = await fs.readFile(summaryFile, "utf8");

  assert.equal(outputs.status, "success");
  assert.equal(outputs.decision, "review");
  assert.equal(outputs["report-path"], ".originfence/out/report.json");
  assert.equal(outputs["summary-path"], ".originfence/out/summary.txt");
  assert.match(summary, /Status: `success`/);
  assert.match(summary, /Decision: `review`/);
  assert.match(summary, /Enforcement mode: observe/);
});

test("github action wrapper produces a neutral non-blocking result when no supported dependency changes are present", async () => {
  const repo = await makeGitRepo(
    {
      "package.json": JSON.stringify({
        name: "fixture-app",
        version: "1.0.0",
        dependencies: {
          lodash: "^4.17.21"
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
              lodash: "^4.17.21"
            }
          },
          "node_modules/lodash": {
            version: "4.17.21",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
          }
        }
      }, null, 2)
    },
    {
      "README.md": "# docs-only change\n"
    }
  );

  const outputFile = path.join(repo.root, "github-output.txt");
  const summaryFile = path.join(repo.root, "github-step-summary.md");

  const result = spawnSync(process.execPath, ["dist/src/github-action.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GITHUB_WORKSPACE: repo.root,
      GITHUB_ACTION_PATH: process.cwd(),
      GITHUB_OUTPUT: outputFile,
      GITHUB_STEP_SUMMARY: summaryFile,
      INPUT_BASE_REV: repo.baseRev
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 0);
  const outputs = await readGitHubOutputs(outputFile);
  const summary = await fs.readFile(summaryFile, "utf8");

  assert.equal(outputs.status, "neutral");
  assert.equal(outputs.decision, "neutral");
  assert.match(summary, /No supported dependency changes were detected/);
});

test("github action wrapper preserves a failure report when repo policy is malformed", async () => {
  const repo = await makeGitRepo(
    {
      "requirements.txt": "# no dependencies\n"
    },
    {
      "requirements.txt": "internal-tooling-lib @ https://packages.example.com/internal-tooling-lib-1.0.0.tar.gz\n",
      ".originfence/policy.yaml": ["version: 2", "sources:", "  deny_direct_urls: maybe"].join("\n")
    }
  );

  const outputFile = path.join(repo.root, "github-output.txt");
  const summaryFile = path.join(repo.root, "github-step-summary.md");

  const result = spawnSync(process.execPath, ["dist/src/github-action.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GITHUB_WORKSPACE: repo.root,
      GITHUB_ACTION_PATH: process.cwd(),
      GITHUB_OUTPUT: outputFile,
      GITHUB_STEP_SUMMARY: summaryFile,
      INPUT_BASE_REV: repo.baseRev
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 1);
  const outputs = await readGitHubOutputs(outputFile);
  const summary = await fs.readFile(summaryFile, "utf8");
  const report = JSON.parse(await fs.readFile(path.join(repo.root, ".originfence", "out", "report.json"), "utf8")) as {
    status: string;
    decision: string;
    summary: string;
    diagnostics?: Array<{ code: string; message: string }>;
  };

  assert.equal(outputs.status, "failure");
  assert.equal(outputs.decision, "neutral");
  assert.equal(report.status, "failure");
  assert.equal(report.decision, "neutral");
  assert.match(report.summary, /Policy schema validation failed/);
  assert.equal(report.diagnostics?.[0]?.code, "EVALUATION_FAILED");
  assert.match(summary, /Policy schema validation failed/);
});

test("github action wrapper derives the base revision from the pull_request event payload when base-rev is omitted", async () => {
  const repo = await makeGitRepo(
    {
      "requirements.txt": "# no dependencies\n"
    },
    {
      "requirements.txt": "internal-tooling-lib @ https://packages.example.com/internal-tooling-lib-1.0.0.tar.gz\n"
    }
  );

  const outputFile = path.join(repo.root, "github-output.txt");
  const summaryFile = path.join(repo.root, "github-step-summary.md");
  const eventFile = path.join(repo.root, "github-event.json");

  await fs.writeFile(eventFile, JSON.stringify({
    pull_request: {
      base: {
        sha: repo.baseRev
      }
    }
  }), "utf8");

  const result = spawnSync(process.execPath, ["dist/src/github-action.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GITHUB_WORKSPACE: repo.root,
      GITHUB_ACTION_PATH: process.cwd(),
      GITHUB_OUTPUT: outputFile,
      GITHUB_STEP_SUMMARY: summaryFile,
      GITHUB_EVENT_PATH: eventFile
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 1);
  const outputs = await readGitHubOutputs(outputFile);

  assert.equal(outputs.status, "failure");
  assert.equal(outputs.decision, "review");
});

test("github action wrapper renders repo issues with manifest and lockfile paths", async () => {
  const repo = await makeGitRepo(
    {
      "requirements.txt": "# no dependencies\n"
    },
    {
      "requirements.txt": "# no dependencies\n",
      "package.json": JSON.stringify(
        {
          name: "fixture-app",
          version: "1.0.0",
          dependencies: {
            lodash: "^4.17.21"
          }
        },
        null,
        2
      )
    }
  );

  const outputFile = path.join(repo.root, "github-output.txt");
  const summaryFile = path.join(repo.root, "github-step-summary.md");

  const result = spawnSync(process.execPath, ["dist/src/github-action.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GITHUB_WORKSPACE: repo.root,
      GITHUB_ACTION_PATH: process.cwd(),
      GITHUB_OUTPUT: outputFile,
      GITHUB_STEP_SUMMARY: summaryFile,
      INPUT_BASE_REV: repo.baseRev
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 1);
  const summary = await fs.readFile(summaryFile, "utf8");
  assert.match(summary, /package\.json -> package-lock\.json/);
  assert.doesNotMatch(summary, /<repo>/);
});

test("github action wrapper emits documented output enums on wrapper-level failure", async () => {
  const failureRoot = path.join(TEST_TMP_ROOT, "gha-fail");
  await fs.mkdir(failureRoot, { recursive: true });
  const workspace = await fs.mkdtemp(path.join(failureRoot, "originfence-gha-fail-"));
  const outputFile = path.join(workspace, "github-output.txt");

  const result = spawnSync(process.execPath, ["dist/src/github-action.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      GITHUB_WORKSPACE: workspace,
      GITHUB_ACTION_PATH: process.cwd(),
      GITHUB_OUTPUT: outputFile
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 2);
  const outputs = await readGitHubOutputs(outputFile);
  assert.equal(outputs.status, "failure");
  assert.equal(outputs.decision, "neutral");
  assert.equal(outputs["changed-subjects"], "0");
});

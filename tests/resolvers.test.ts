import assert from "node:assert/strict";
import test from "node:test";

import { resolveRepoDiff } from "../src/resolvers";
import { makeTempDir, writeFiles } from "./helpers";

test("resolveRepoDiff treats common requirements specifiers as registry inputs instead of unknown sources", async () => {
  const basePath = await makeTempDir("originfence-resolver-base-");
  const headPath = await makeTempDir("originfence-resolver-head-");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": [
      "--extra-index-url https://download.example/simple",
      "requests>=2.31,<3 ; python_version >= \"3.10\""
    ].join("\n")
  });

  const result = await resolveRepoDiff(basePath, headPath);

  assert.equal(result.issues.length, 0);
  assert.equal(result.subjects.length, 1);
  assert.equal(result.subjects[0]?.name, "requests");
  assert.equal(result.subjects[0]?.source_type, "registry");
  assert.equal(result.subjects[0]?.version, null);
});

test("resolveRepoDiff follows included requirements files and detects spec-only changes", async () => {
  const basePath = await makeTempDir("originfence-requirements-include-base-");
  const headPath = await makeTempDir("originfence-requirements-include-head-");

  await writeFiles(basePath, {
    "requirements.txt": "-r requirements-dev.txt\n",
    "requirements-dev.txt": "requests>=2.31\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "-r requirements-dev.txt\n",
    "requirements-dev.txt": "requests>=2.32\n"
  });

  const result = await resolveRepoDiff(basePath, headPath);

  assert.equal(result.issues.length, 0);
  assert.equal(result.subjects.length, 1);
  assert.equal(result.subjects[0]?.name, "requests");
  assert.equal(result.subjects[0]?.source_ref, "requests>=2.32");
  assert.equal(result.subjects[0]?.manifest_path, "requirements-dev.txt");
});

test("resolveRepoDiff parses editable VCS requirements instead of dropping them", async () => {
  const basePath = await makeTempDir("originfence-editable-base-");
  const headPath = await makeTempDir("originfence-editable-head-");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "-e git+https://github.com/example/internal-tooling-lib.git@9f2e1d4#egg=internal-tooling-lib\n"
  });

  const result = await resolveRepoDiff(basePath, headPath);

  assert.equal(result.issues.length, 0);
  assert.equal(result.subjects.length, 1);
  assert.equal(result.subjects[0]?.name, "internal-tooling-lib");
  assert.equal(result.subjects[0]?.source_type, "vcs");
});

test("resolveRepoDiff treats npm registry tarball URLs in package-lock.json as registry sources", async () => {
  const basePath = await makeTempDir("originfence-npm-registry-base-");
  const headPath = await makeTempDir("originfence-npm-registry-head-");

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
  });

  const result = await resolveRepoDiff(basePath, headPath);

  assert.equal(result.issues.length, 0);
  assert.equal(result.subjects.length, 1);
  assert.equal(result.subjects[0]?.name, "lodash");
  assert.equal(result.subjects[0]?.source_type, "registry");
  assert.equal(result.subjects[0]?.registry_host, "registry.npmjs.org");
});

test("resolveRepoDiff keeps explicit npm tarball specs as direct URLs", async () => {
  const basePath = await makeTempDir("originfence-npm-tarball-base-");
  const headPath = await makeTempDir("originfence-npm-tarball-head-");

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
        "custom-lib": "https://packages.example.com/custom-lib-1.2.3.tgz"
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
            "custom-lib": "https://packages.example.com/custom-lib-1.2.3.tgz"
          }
        },
        "node_modules/custom-lib": {
          version: "1.2.3",
          resolved: "https://packages.example.com/custom-lib-1.2.3.tgz"
        }
      }
    }, null, 2)
  });

  const result = await resolveRepoDiff(basePath, headPath);

  assert.equal(result.issues.length, 0);
  assert.equal(result.subjects.length, 1);
  assert.equal(result.subjects[0]?.name, "custom-lib");
  assert.equal(result.subjects[0]?.source_type, "direct_url");
  assert.equal(result.subjects[0]?.source_ref, "https://packages.example.com/custom-lib-1.2.3.tgz");
});

test("resolveRepoDiff ignores constraint files as install declarations", async () => {
  const basePath = await makeTempDir("originfence-constraints-base-");
  const headPath = await makeTempDir("originfence-constraints-head-");

  await writeFiles(basePath, {
    "requirements.txt": "# no dependencies\n"
  });

  await writeFiles(headPath, {
    "requirements.txt": "-c constraints.txt\nrequests>=2.31\n",
    "constraints.txt": "urllib3==2.2.1\n"
  });

  const result = await resolveRepoDiff(basePath, headPath);

  assert.equal(result.issues.length, 0);
  assert.equal(result.subjects.length, 1);
  assert.equal(result.subjects[0]?.name, "requests");
});

test("resolveRepoDiff keeps legacy npm lockfile direct URLs when the lock entry declares them", async () => {
  const basePath = await makeTempDir("originfence-legacy-npm-base-");
  const headPath = await makeTempDir("originfence-legacy-npm-head-");

  await writeFiles(basePath, {
    "package.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0"
    }, null, 2),
    "package-lock.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      lockfileVersion: 2,
      requires: true,
      dependencies: {}
    }, null, 2)
  });

  await writeFiles(headPath, {
    "package.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0"
    }, null, 2),
    "package-lock.json": JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      lockfileVersion: 2,
      requires: true,
      dependencies: {
        "legacy-direct": {
          version: "https://packages.example.com/legacy-direct-1.0.0.tgz",
          resolved: "https://packages.example.com/legacy-direct-1.0.0.tgz"
        }
      }
    }, null, 2)
  });

  const result = await resolveRepoDiff(basePath, headPath);

  assert.equal(result.issues.length, 0);
  assert.equal(result.subjects.length, 1);
  assert.equal(result.subjects[0]?.name, "legacy-direct");
  assert.equal(result.subjects[0]?.source_type, "direct_url");
});

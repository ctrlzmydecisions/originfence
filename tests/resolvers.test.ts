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

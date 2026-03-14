# Changelog

All notable changes to OriginFence should be recorded in this file.

## 0.1.1-alpha - 2026-03-14

Alpha patch release:
- fix npm lockfile source classification so normal registry tarball URLs are not misclassified as `DIRECT_URL_SOURCE`
- stop treating Python constraint files as dependency declarations during `requirements.txt` parsing
- fail closed when required provenance cannot be verified because trust-root or verifier sources are unavailable
- tighten npm provenance registry host matching to explicit trusted hosts
- normalize fixture policy source paths so CI stays stable across local and GitHub-hosted environments

## 0.1.0-alpha - 2026-03-14

Initial public alpha surface:
- GitHub Action for pull request and merge queue dependency trust gating
- policy and waiver support through `.originfence/policy.yaml` and `.originfence/waivers.yaml`
- observe mode so teams can surface findings without failing required checks during rollout
- `originfence init` plus shipped presets for `observe`, `balanced`, and `strict` starting points
- canonical JSON report plus human-readable summaries
- sticky PR comments and artifact upload support
- npm and PyPI dependency change evaluation
- malicious-package intelligence from OpenSSF via OSV, GitHub npm malware advisories, and local emergency override files
- prebuilt bundled Action packaging with no runtime dependency install step
- scheduled live canaries for known npm and PyPI packages plus live source adapters

import fs from "node:fs/promises";
import YAML from "yaml";

import { assertValidWaivers } from "./schema";
import type { Subject, Waiver, WaiversFile } from "./types";

export async function loadWaivers(waiverPath?: string): Promise<WaiversFile> {
  if (!waiverPath) {
    return { version: 1, waivers: [] };
  }

  const content = await fs.readFile(waiverPath, "utf8");
  return assertValidWaivers(YAML.parse(content));
}

export function isWaiverExpired(waiver: Waiver, now: string): boolean {
  return Date.parse(waiver.expires_at) <= Date.parse(now);
}

export function doesWaiverMatchSubject(waiver: Waiver, subject: Subject): boolean {
  const { scope } = waiver;

  if (scope.ecosystem && scope.ecosystem !== subject.ecosystem) {
    return false;
  }

  if (scope.package && scope.package !== subject.name) {
    return false;
  }

  if (scope.version && scope.version !== (subject.version ?? "")) {
    return false;
  }

  if (scope.path) {
    const manifestPath = subject.manifest_path ?? "";
    const lockfilePath = subject.lockfile_path ?? "";

    if (scope.path !== manifestPath && scope.path !== lockfilePath) {
      return false;
    }
  }

  return true;
}

export function findMatchingWaivers(waivers: Waiver[], subject: Subject, reasonCode: string, now: string): Waiver[] {
  return waivers.filter((waiver) => {
    if (isWaiverExpired(waiver, now)) {
      return false;
    }

    if (!waiver.reason_codes.includes(reasonCode)) {
      return false;
    }

    return doesWaiverMatchSubject(waiver, subject);
  });
}

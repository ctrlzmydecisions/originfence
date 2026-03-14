import type { EnforcementMode } from "./types";

export function parseEnforcementMode(value: string | undefined, fallback: EnforcementMode = "enforce"): EnforcementMode {
  if (!value || value.length === 0) {
    return fallback;
  }

  if (value === "enforce" || value === "observe") {
    return value;
  }

  throw new Error(`Unsupported enforcement mode: ${value}. Use enforce or observe.`);
}

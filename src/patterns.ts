function escapeRegExp(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

export function matchesPattern(value: string, pattern: string): boolean {
  const wildcardToken = "__PTG_WILDCARD__";
  const regex = new RegExp(`^${escapeRegExp(pattern.replaceAll("*", wildcardToken)).replaceAll(wildcardToken, ".*")}$`);
  return regex.test(value);
}

export function matchesAnyPattern(value: string, patterns: string[] | undefined): boolean {
  if (!patterns || patterns.length === 0) {
    return false;
  }

  return patterns.some((pattern) => matchesPattern(value, pattern));
}

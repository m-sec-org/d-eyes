export const RESERVED_AGENT_LABEL_KEYS = ['allow_memscan', 'mode'] as const;
export const RESERVED_AGENT_LABEL_PREFIXES = ['build.'] as const;

export function isReservedAgentLabelKey(key: string) {
  return (
    RESERVED_AGENT_LABEL_KEYS.includes(key as (typeof RESERVED_AGENT_LABEL_KEYS)[number]) ||
    RESERVED_AGENT_LABEL_PREFIXES.some((prefix) => key.startsWith(prefix))
  );
}

export function splitAgentLabels(labels?: Record<string, string>) {
  const reserved: Record<string, string> = {};
  const editable: Record<string, string> = {};
  for (const [key, value] of Object.entries(labels ?? {})) {
    if (isReservedAgentLabelKey(key)) {
      reserved[key] = value;
    } else {
      editable[key] = value;
    }
  }
  return { reserved, editable };
}

export function formatAgentLabelPairs(labels: Record<string, string>) {
  return Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}:${value}`)
    .join('\n');
}


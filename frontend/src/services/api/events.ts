import httpClient from '../http';
import {
  SystemEventAggregatesSchema,
  SystemEventListResponseSchema,
} from './schemas';
import type {
  SystemEventAggregates,
  SystemEventListResponse,
} from '../types';

const MIN_LIMIT = 1;
const MAX_LIMIT = 1000;
const DEFAULT_LIMIT = 100;

type SortDirection = 'asc' | 'desc';

type EventQueryDefaults = {
  limit?: number;
  sort?: SortDirection;
};

type NormalizeOptions = {
  includeCursor?: boolean;
};

export interface SystemEventQueryParams {
  agent_id?: string;
  collector?: string;
  collector_kind?: string;
  event_type?: string;
  source?: string;
  priorities?: string[];
  storageTiers?: string[];
  since?: string;
  until?: string;
  limit?: number;
  sort?: SortDirection;
  cursor_id?: string;
  cursor_time?: string;
}

export interface NormalizedSystemEventQuery extends Omit<SystemEventQueryParams, 'storageTiers'> {
  storageTiers?: string[];
  priorities?: string[];
  limit: number;
  sort: SortDirection;
}

const clampLimit = (value: number) => {
  if (Number.isNaN(value)) {
    return DEFAULT_LIMIT;
  }
  return Math.min(Math.max(Math.floor(value), MIN_LIMIT), MAX_LIMIT);
};

const sanitizeList = (values?: string[]) =>
  values
    ?.map((value) => value.trim())
    .filter((value) => value.length > 0) ?? [];

export function normalizeEventQueryParams(
  params: SystemEventQueryParams = {},
  defaults: EventQueryDefaults = {},
  options: NormalizeOptions = {}
): NormalizedSystemEventQuery {
  const limitBase = defaults.limit ?? params.limit ?? DEFAULT_LIMIT;
  const limit = clampLimit(limitBase);
  const sort = (defaults.sort ?? params.sort ?? 'desc') === 'asc' ? 'asc' : 'desc';
  const priorities = Array.from(new Set(sanitizeList(params.priorities))).sort();
  const storageTiers = Array.from(new Set(sanitizeList(params.storageTiers))).sort();

  const normalized: NormalizedSystemEventQuery = {
    ...params,
    priorities: priorities.length ? priorities : undefined,
    storageTiers: storageTiers.length ? storageTiers : undefined,
    limit,
    sort,
  };

  if (!options.includeCursor) {
    delete normalized.cursor_id;
    delete normalized.cursor_time;
  }

  return normalized;
}

export function serializeEventQueryKey(
  params: SystemEventQueryParams = {},
  defaults: EventQueryDefaults = {}
): string {
  const normalized = normalizeEventQueryParams(params, defaults);
  return JSON.stringify(normalized);
}

function toHttpParams(query: NormalizedSystemEventQuery): Record<string, string | number> {
  const params: Record<string, string | number> = {};

  if (query.agent_id) params.agent_id = query.agent_id;
  if (query.collector) params.collector = query.collector;
  if (query.collector_kind) params.collector_kind = query.collector_kind;
  if (query.event_type) params.event_type = query.event_type;
  if (query.source) params.source = query.source;
  if (query.priorities?.length) params.priority = query.priorities.join(',');
  if (query.storageTiers?.length) params.storage_tier = query.storageTiers.join(',');
  if (query.since) params.since = query.since;
  if (query.until) params.until = query.until;
  params.limit = query.limit;
  params.sort = query.sort;
  if (query.cursor_id && query.cursor_time) {
    params.cursor_id = query.cursor_id;
    params.cursor_time = query.cursor_time;
  }

  return params;
}

export async function fetchSystemEvents(
  params: SystemEventQueryParams = {}
): Promise<SystemEventListResponse> {
  const normalized = normalizeEventQueryParams(params, {}, { includeCursor: true });
  const res = await httpClient.get('/events', { params: toHttpParams(normalized) });
  return SystemEventListResponseSchema.parse(res.data);
}

export async function fetchDetectionEvents(
  params: SystemEventQueryParams = {}
): Promise<SystemEventListResponse> {
  return fetchSystemEvents({ ...params, event_type: 'detection.alert' });
}

export async function fetchSystemEventStats(
  params: SystemEventQueryParams = {}
): Promise<SystemEventAggregates> {
  const normalized = normalizeEventQueryParams(params);
  const res = await httpClient.get('/events/stats', { params: toHttpParams(normalized) });
  return SystemEventAggregatesSchema.parse(res.data);
}

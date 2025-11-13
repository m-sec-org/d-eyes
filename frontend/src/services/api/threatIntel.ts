import httpClient from '../http';
import {
  ThreatIntelIndicatorSchema,
  ThreatIntelLookupResponseSchema,
  ThreatIntelSampleSchema,
} from './schemas';
import type { ThreatIntelLookupResponse, ThreatIntelIndicator, ThreatIntelSample } from '../types';

export interface LookupPayload {
  indicator: string;
  kind?: string;
  force?: boolean;
  sources?: string[];
}

export async function lookupIndicator(payload: LookupPayload): Promise<ThreatIntelLookupResponse> {
  const res = await httpClient.post('/threat-intel/lookup', payload);
  return ThreatIntelLookupResponseSchema.parse(res.data);
}

export async function fetchIndicator(indicator: string): Promise<ThreatIntelIndicator> {
  const res = await httpClient.get(`/threat-intel/iocs/${encodeURIComponent(indicator)}`);
  return ThreatIntelIndicatorSchema.parse(res.data);
}

export async function fetchSample(sampleId: string): Promise<ThreatIntelSample> {
  const res = await httpClient.get(`/threat-intel/samples/${sampleId}`);
  return ThreatIntelSampleSchema.parse(res.data);
}

import { httpClient } from '@/services/http';

export type PluginRecord = {
  manifest: {
    name: string;
    version: string;
    description?: string;
  };
  status: string;
  reason?: string;
  installed_at: string;
};

export async function listPlugins() {
  const res = await httpClient.get<PluginRecord[]>('/plugins');
  return res.data;
}

export async function installPlugin(manifest: string, encoding: 'plain' | 'base64' = 'plain') {
  return httpClient.post('/plugins', { manifest, encoding });
}

export async function rollbackPlugin(name: string) {
  return httpClient.post(`/plugins/${name}/rollback`);
}

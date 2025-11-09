import type { ReactNode } from 'react';
import { SWRConfig } from 'swr';
import { ConfigProvider, theme } from 'antd';
import { AuthProvider } from './AuthProvider';
import httpClient from '@/services/http';

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#1677ff',
          borderRadius: 12,
          fontSize: 14,
        },
      }}
    >
      <SWRConfig value={{ fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
        <AuthProvider>{children}</AuthProvider>
      </SWRConfig>
    </ConfigProvider>
  );
}

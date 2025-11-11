import type { ReactNode } from 'react';
import { SWRConfig } from 'swr';
import { ConfigProvider } from 'antd';
import { AuthProvider } from './AuthProvider';
import httpClient from '@/services/http';
import { antdThemeConfig } from '@/theme/tokens';

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ConfigProvider theme={antdThemeConfig}>
      <SWRConfig value={{ fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
        <AuthProvider>{children}</AuthProvider>
      </SWRConfig>
    </ConfigProvider>
  );
}

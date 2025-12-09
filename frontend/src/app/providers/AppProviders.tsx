import type { ReactNode } from 'react';
import { SWRConfig } from 'swr';
import { App as AntdApp, ConfigProvider } from 'antd';
import { AuthProvider } from './AuthProvider';
import httpClient from '@/services/http';
import { antdThemeConfig } from '@/theme/tokens';

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ConfigProvider theme={antdThemeConfig}>
      <AntdApp>
        <SWRConfig value={{ fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
          <AuthProvider>{children}</AuthProvider>
        </SWRConfig>
      </AntdApp>
    </ConfigProvider>
  );
}

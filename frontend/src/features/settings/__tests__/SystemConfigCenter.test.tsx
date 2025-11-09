import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { SWRConfig } from 'swr';
import { SystemConfigCenter } from '../SystemConfigCenter';
import httpClient from '@/services/http';
import { AuthProvider } from '@/app/providers/AuthProvider';

const renderWithProviders = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
      <AuthProvider>
        <SystemConfigCenter />
      </AuthProvider>
    </SWRConfig>
  );

describe('SystemConfigCenter', () => {
  it('renders template table and global config form', async () => {
    renderWithProviders();
    await waitFor(() => expect(screen.getByText('系统配置中心')).toBeInTheDocument());
    expect(screen.getByLabelText(/风险阈值/)).toBeInTheDocument();
    expect(screen.getByText(/任务模板/)).toBeInTheDocument();
  });
});

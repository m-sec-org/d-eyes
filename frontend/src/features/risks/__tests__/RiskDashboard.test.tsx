import { render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { describe, it, expect } from 'vitest';
import { RiskDashboard } from '../RiskDashboard';
import httpClient from '@/services/http';
import { AuthProvider } from '@/app/providers/AuthProvider';

function renderWithProviders() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
      <AuthProvider>
        <RiskDashboard />
      </AuthProvider>
    </SWRConfig>
  );
}

describe('RiskDashboard', () => {
  it('renders risk cards and timeline items', async () => {
    renderWithProviders();
    await waitFor(() => expect(screen.getByRole('region', { name: '风险时间线' })).toBeInTheDocument());
    expect(screen.getByText(/风险监控/)).toBeInTheDocument();
    expect(await screen.findByText(/总风险事件/)).toBeInTheDocument();
  });
});

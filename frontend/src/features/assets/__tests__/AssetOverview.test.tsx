import { render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { describe, it, expect } from 'vitest';
import { AssetOverview } from '../AssetOverview';
import httpClient from '@/services/http';
import { AuthProvider } from '@/app/providers/AuthProvider';

function renderComponent() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
      <AuthProvider>
        <AssetOverview />
      </AuthProvider>
    </SWRConfig>
  );
}

describe('AssetOverview', () => {
  it('renders asset cards and table rows', async () => {
    renderComponent();
    await waitFor(() => expect(screen.getByText('资产视图')).toBeInTheDocument());
    expect(screen.getByText('在线资产')).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText(/查看/).length).toBeGreaterThan(0));
  });
});

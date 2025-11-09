import { render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { describe, it, expect } from 'vitest';
import { AssetOverview } from '../AssetOverview';
import httpClient from '@/services/http';
import { AuthProvider } from '@/app/providers/AuthProvider';

function setup() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
      <AuthProvider>
        <AssetOverview />
      </AuthProvider>
    </SWRConfig>
  );
}

describe('AssetOverview performance characteristics', () => {
  it('renders limited rows at once via virtualization', async () => {
    setup();
    await waitFor(() => expect(screen.getByRole('region', { name: '资产列表' })).toBeInTheDocument());
    const rows = document.querySelectorAll('.table-row');
    expect(rows.length).toBeLessThan(15);
  });
});

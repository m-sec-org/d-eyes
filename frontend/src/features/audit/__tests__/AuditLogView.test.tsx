import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { SWRConfig } from 'swr';
import { AuditLogView } from '../AuditLogView';
import httpClient from '@/services/http';
import { AuthProvider } from '@/app/providers/AuthProvider';

const renderAudit = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), fetcher: (url: string) => httpClient.get(url).then((res) => res.data) }}>
      <AuthProvider>
        <AuditLogView />
      </AuthProvider>
    </SWRConfig>
  );

describe('AuditLogView', () => {
  it('renders audit logs with filter controls', async () => {
    renderAudit();
    await waitFor(() => expect(screen.getByText('审计日志')).toBeInTheDocument());
    expect(screen.getByRole('combobox')).toBeInTheDocument();
  });
});

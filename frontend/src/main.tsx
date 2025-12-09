import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import 'antd/dist/reset.css';
import './index.css';
import './lib/antdCompat';
import App from './App';
import { AppProviders } from './app/providers/AppProviders';

async function enableMocking() {
  if (import.meta.env.DEV && import.meta.env.VITE_USE_MSW !== 'false') {
    try {
      const { worker } = await import('./mocks/browser');
      await worker.start({ onUnhandledRequest: 'bypass' });
    } catch (error) {
      console.warn('[MSW] 启动失败，已回退至无 Mock 模式：', error);
    }
  }
}

async function bootstrap() {
  await enableMocking();
  const rootElement = document.getElementById('root');
  if (!rootElement) {
    throw new Error('Root element not found');
  }
  createRoot(rootElement).render(
    <StrictMode>
      <AppProviders>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AppProviders>
    </StrictMode>
  );
}

bootstrap();

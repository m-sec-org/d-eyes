import httpClient, { setAuthToken } from '../http';
import { AuthSessionSchema } from './schemas';

export interface LoginPayload {
  username: string;
  password: string;
}

export const authApi = {
  async login(payload: LoginPayload) {
    const res = await httpClient.post('/auth/login', payload);
    const parsed = AuthSessionSchema.parse(res.data);
    setAuthToken(parsed.token);
    return parsed;
  },
  async refresh(refreshToken: string) {
    const res = await httpClient.post('/auth/refresh', { refresh_token: refreshToken });
    const parsed = AuthSessionSchema.parse(res.data);
    setAuthToken(parsed.token);
    return parsed;
  },
  async logout() {
    try {
      await httpClient.post('/auth/logout');
    } catch (error) {
      if (import.meta.env.DEV) {
        console.warn('logout failed', error);
      }
    } finally {
      setAuthToken(null);
    }
  },
};

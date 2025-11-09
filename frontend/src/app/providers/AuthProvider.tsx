import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import dayjs from 'dayjs';
import { authApi } from '@/services/api/auth';
import type { AuthSession } from '@/services/types';

interface AuthContextValue {
  session?: AuthSession;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  expiresAt?: string;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const STORAGE_KEY = 'd-eyes:session';

const AUTO_LOGIN_USERNAME = 'ops.lead';
const AUTO_LOGIN_PASSWORD = 'Passw0rd!';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | undefined>(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as AuthSession;
    } catch {
      return undefined;
    }
  });
  const [loading, setLoading] = useState(!session);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const persistSession = useCallback((payload?: AuthSession) => {
    if (typeof window === 'undefined') {
      setSession(payload);
      return;
    }
    if (!payload) {
      window.localStorage.removeItem(STORAGE_KEY);
      setSession(undefined);
      return;
    }
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    setSession(payload);
  }, []);

  const scheduleRefresh = useCallback(
    (payload: AuthSession) => {
      if (refreshTimer.current) {
        clearTimeout(refreshTimer.current);
      }
      const msUntilExpiry = payload.expires_in * 1000;
      const refreshIn = Math.max(msUntilExpiry - 5 * 60 * 1000, 30 * 1000);
      refreshTimer.current = globalThis.setTimeout(async () => {
        const refreshed = await authApi.refresh(payload.refresh_token);
        persistSession({
          ...refreshed,
          user: refreshed.user,
        });
      }, refreshIn);
    },
    [persistSession]
  );

  const login = useCallback(
    async (username: string, password: string) => {
      setLoading(true);
      try {
        const result = await authApi.login({ username, password });
        persistSession(result);
        scheduleRefresh(result);
      } finally {
        setLoading(false);
      }
    },
    [persistSession, scheduleRefresh]
  );

  const logout = useCallback(async () => {
    await authApi.logout();
    if (refreshTimer.current) {
      clearTimeout(refreshTimer.current);
    }
    persistSession(undefined);
  }, [persistSession]);

  useEffect(() => {
    if (session) {
      scheduleRefresh(session);
      setLoading(false);
      return;
    }
    if (import.meta.env.VITE_AUTO_LOGIN !== 'false') {
      login(AUTO_LOGIN_USERNAME, AUTO_LOGIN_PASSWORD).catch(() => setLoading(false));
    }
  }, [login, scheduleRefresh, session]);

  const value = useMemo(
    () => ({
      session,
      loading,
      login,
      logout,
      expiresAt: session ? dayjs().add(session.expires_in, 'seconds').toISOString() : undefined,
    }),
    [loading, login, logout, session]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuthContext must be used within AuthProvider');
  }
  return ctx;
}

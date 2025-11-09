import { useAuthContext } from '@/app/providers/AuthProvider';

export function useAuth() {
  return useAuthContext();
}

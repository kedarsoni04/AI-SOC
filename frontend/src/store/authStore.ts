/**
 * Auth store using Zustand.
 * Persists token to localStorage.
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User, LoginRequest, TokenResponse } from '../types';
import { post } from '../services/api';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
  setUser: (user: User) => void;
  clearError: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      login: async (credentials) => {
        set({ isLoading: true, error: null });
        try {
          const data = await post<TokenResponse>('/auth/login', credentials);
          localStorage.setItem('access_token', data.access_token);
          localStorage.setItem('refresh_token', data.refresh_token);
          set({
            user: data.user,
            accessToken: data.access_token,
            isAuthenticated: true,
            isLoading: false,
          });
        } catch (err: unknown) {
          const msg =
            (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
            'Login failed. Please check your credentials.';
          set({ isLoading: false, error: msg });
          throw err;
        }
      },

      logout: async () => {
        try {
          await post('/auth/logout');
        } catch {
          // Ignore logout errors
        } finally {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          set({ user: null, accessToken: null, isAuthenticated: false });
        }
      },

      setUser: (user) => set({ user }),
      clearError: () => set({ error: null }),
    }),
    {
      name: 'soc-auth',
      partialize: (state) => ({
        user: state.user,
        accessToken: state.accessToken,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);

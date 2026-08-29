/**
 * Axios API client with automatic JWT token injection and error handling.
 */
import axios, { AxiosError } from 'axios';
import type { AxiosInstance, AxiosResponse } from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const API_PREFIX = '/api/v1';

// ── Axios instance ─────────────────────────────────────────────────────────────
const api: AxiosInstance = axios.create({
  baseURL: `${BASE_URL}${API_PREFIX}`,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// ── Request interceptor: inject JWT ───────────────────────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response interceptor: handle 401 ─────────────────────────────────────────
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error: AxiosError) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// ── Type-safe helpers ──────────────────────────────────────────────────────────
export const get = <T>(url: string, params?: Record<string, unknown>) =>
  api.get<T>(url, { params }).then((r) => r.data);

export const post = <T>(url: string, data?: unknown) =>
  api.post<T>(url, data).then((r) => r.data);

export const patch = <T>(url: string, data?: unknown) =>
  api.patch<T>(url, data).then((r) => r.data);

export const del = <T>(url: string) =>
  api.delete<T>(url).then((r) => r.data);

export default api;

// ── WebSocket helper ──────────────────────────────────────────────────────────
const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

export const createWebSocket = (): WebSocket => {
  const ws = new WebSocket(`${WS_BASE}/ws`);
  return ws;
};

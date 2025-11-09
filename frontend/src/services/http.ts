import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '/api/v1';

let authToken: string | null = null;

export const setAuthToken = (token: string | null) => {
  authToken = token;
};

export const httpClient = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
});

httpClient.interceptors.request.use((config) => {
  if (authToken) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${authToken}`;
  }
  return config;
});

httpClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // 统一错误日志，后续可上报
    if (import.meta.env.DEV) {
      console.error('[API ERROR]', error);
    }
    return Promise.reject(error);
  }
);

export default httpClient;

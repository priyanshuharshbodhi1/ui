import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

declare module 'axios' {
  interface AxiosRequestConfig {
    _retry?: boolean;
  }
}
import { toast } from 'react-hot-toast';
import { refreshToken } from '../api/auth';
import { isTokenExpired, getTimeUntilExpiration } from '../utils/tokenUtils';
import { logout } from '../hooks/useAuth';

export const api = axios.create({
  baseURL: process.env.VITE_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  },
});

let refreshTokenPromise: Promise<string> | null = null;

async function refreshAccessToken(): Promise<string> {
  if (refreshTokenPromise) {
    return refreshTokenPromise;
  }

  const oldRefreshToken = localStorage.getItem('refreshToken');
  if (!oldRefreshToken) {
    return Promise.reject(new Error('No refresh token available'));
  }

  refreshTokenPromise = new Promise<string>((resolve, reject) => {
    refreshToken({ refreshToken: oldRefreshToken })
      .then(response => {
        localStorage.setItem('jwtToken', response.token);
        localStorage.setItem('refreshToken', response.refreshToken);
        resolve(response.token);
      })
      .catch(err => {
        logout();
        reject(err);
      })
      .finally(() => {
        refreshTokenPromise = null;
      });
  });

  return refreshTokenPromise;
}

// Add request interceptor to include JWT token in headers and check for token refresh needs
api.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('jwtToken');
    if (token) {
      if (isTokenExpired(token)) {
        try {
          const newToken = await refreshAccessToken();
          config.headers.Authorization = `Bearer ${newToken}`;
        } catch {
          console.warn('Token refresh failed');
        }
      } else {
        config.headers.Authorization = `Bearer ${token}`;

        const timeUntilExpiration = getTimeUntilExpiration(token);
        if (timeUntilExpiration > 0 && timeUntilExpiration < 5 * 60 * 1000) {
          refreshAccessToken().catch(() => {});
        }
      }
    }
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  response => response,
  async (error: AxiosError<{ message: string; error: string }>) => {
    if (!error.config || !error.response) {
      return Promise.reject(error);
    }

    if (error.response.status === 401) {
      const originalRequest = error.config;
      const refreshTokenExists = localStorage.getItem('refreshToken');
      const isAuthCheck = originalRequest.url?.includes('/api/me');
      const isRefreshRequest = originalRequest.url?.includes('/auth/refresh');

      if (refreshTokenExists && !isRefreshRequest && !isAuthCheck && !originalRequest._retry) {
        originalRequest._retry = true;

        try {
          const newToken = await refreshAccessToken();

          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
          }

          return api(originalRequest);
        } catch (refreshError) {
          console.warn('Token refresh failed');
          toast.error('Your session has expired. Please log in again.');
          logout();
          return Promise.reject(refreshError);
        }
      } else if (isRefreshRequest) {
        console.warn('Invalid refresh token');
        toast.error('Your session has expired. Please log in again.');
        logout();
      } else if (!isAuthCheck) {
        toast.error('Authentication required. Please log in.');
      } else {
        console.log('Auth verification failed, ignoring toast');
      }
    } else {
      const errorMessage =
        error.response?.data?.message || error.response?.data?.error || error.message;
      toast.error(errorMessage);
    }

    return Promise.reject(error);
  }
);

// Helper function to get WebSocket URL with proper protocol and base URL
export const getWebSocketUrl = (path: string): string => {
  const baseUrl = process.env.VITE_BASE_URL || '';

  const wsProtocol = baseUrl.startsWith('https') ? 'wss' : 'ws';

  const baseUrlWithoutProtocol = baseUrl.replace(/^https?:\/\//, '');

  return `${wsProtocol}://${baseUrlWithoutProtocol}${path}`;
};

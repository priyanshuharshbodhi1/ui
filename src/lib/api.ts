import axios, { AxiosError } from 'axios';
import { toast } from 'react-hot-toast';
import { isTokenExpired } from '../utils/tokenUtils';
import { logout } from '../hooks/useAuth';

export const api = axios.create({
  baseURL: process.env.VITE_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor to include JWT token in headers and check for expiration
api.interceptors.request.use(
  config => {
    const token = localStorage.getItem('jwtToken');
    if (token) {
      // Check if token is expired before adding it to headers
      if (isTokenExpired(token)) {
        // Token is expired, logout and clear it
        console.warn('Token expired, logging out');
        logout();
        // Don't add expired token to request
      } else {
        // Token is valid, add to headers
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

// Add response interceptors with proper error typing and token expiration handling
api.interceptors.response.use(
  response => response,
  (error: AxiosError<{ message: string; error: string }>) => {
    // Handle global error cases
    const errorMessage =
      error.response?.data?.message || error.response?.data?.error || error.message;

    console.error('API Error:', errorMessage);

    // Handle 401 Unauthorized errors (expired or invalid token)
    if (error.response?.status === 401) {
      const isAuthCheck = error.config?.url?.includes('/api/me');
      const token = localStorage.getItem('jwtToken');
      
      if (token && !isAuthCheck) {
        // If we have a token and this is not an auth check endpoint,
        // the token is likely expired or invalid - log out the user
        console.warn('Received 401 from API, logging out user');
        logout();
        toast.error('Your session has expired. Please log in again.');
      } else if (!isAuthCheck) {
        // For non-auth-check endpoints, show error message
        toast.error('Authentication required. Please log in.');
      } else {
        // For auth check endpoints, silently fail
        console.log('Auth verification failed, ignoring toast');
      }
    } else {
      // For all other errors, show toast notification
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

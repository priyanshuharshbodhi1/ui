import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { VerifyToken } from '../api/auth';
import { AUTH_QUERY_KEY } from '../api/auth/constant';
import { isTokenExpired, getTimeUntilExpiration } from '../utils/tokenUtils';

export const useAuth = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Auto-refresh logic when token is about to expire
  useEffect(() => {
    const token = localStorage.getItem('jwtToken');
    if (token) {
      // Check if token is already expired
      if (isTokenExpired(token)) {
        console.warn('Token already expired on auth mount');
        logout();
        return;
      }

      // Get time until expiration and set up auto-refresh
      const timeUntilExpiration = getTimeUntilExpiration(token);

      // If token is about to expire in the next 5 minutes, refresh auth state
      if (timeUntilExpiration > 0 && timeUntilExpiration < 5 * 60 * 1000) {
        console.log(
          `Token expiring soon (${Math.round(timeUntilExpiration / 1000)}s), refreshing auth state`
        );
        queryClient.invalidateQueries({ queryKey: AUTH_QUERY_KEY });
      }

      // Set up a timer to check token expiration and logout when it expires
      // This handles cases where the user has the app open but isn't making requests
      const expirationTimer = setTimeout(() => {
        console.warn('Token expired via timer, logging out');
        logout();
        navigate('/login', { replace: true });
      }, timeUntilExpiration);

      // Clean up timer on unmount
      return () => clearTimeout(expirationTimer);
    }
  }, [navigate, queryClient]);

  return useQuery({
    queryKey: AUTH_QUERY_KEY,
    queryFn: async () => {
      const token = localStorage.getItem('jwtToken');

      if (!token) {
        return { isAuthenticated: false };
      }

      // Check client-side if token is expired before making API call
      if (isTokenExpired(token)) {
        console.warn('Token expired, skipping verification');
        return { isAuthenticated: false, expired: true };
      }

      try {
        await VerifyToken(token);
        return { isAuthenticated: true };
      } catch (error) {
        return { isAuthenticated: false, error };
      }
    },
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: true,
    refetchOnMount: true,
    retry: 1,
  });
};

export const useAuthActions = () => {
  const queryClient = useQueryClient();

  return {
    logout: () => {
      localStorage.removeItem('jwtToken');
      localStorage.removeItem('refreshToken');
      localStorage.setItem('tokenRemovalTime', Date.now().toString());
      queryClient.invalidateQueries({ queryKey: AUTH_QUERY_KEY });
    },
    refreshAuth: () => {
      queryClient.invalidateQueries({ queryKey: AUTH_QUERY_KEY });
    },
  };
};

export const logout = () => {
  localStorage.removeItem('jwtToken');
  localStorage.removeItem('refreshToken');
  localStorage.setItem('tokenRemovalTime', Date.now().toString());
  window.dispatchEvent(new Event('storage'));
};

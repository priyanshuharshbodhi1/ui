/**
 * Token utility functions for JWT handling
 */

interface JwtPayload {
  exp: number;
  iat: number;
  iss: string;
  username: string;
  permissions: string[];
}

/**
 * Parse a JWT token without verification
 * @param token JWT token string
 * @returns Decoded token payload or null if invalid
 */
export const parseJwt = (token: string): JwtPayload | null => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error parsing JWT:', error);
    return null;
  }
};

/**
 * Check if a token is expired
 * @param token JWT token string
 * @returns true if token is expired or invalid, false otherwise
 */
export const isTokenExpired = (token: string): boolean => {
  if (!token) return true;
  
  const payload = parseJwt(token);
  if (!payload) return true;
  
  // Get current time in seconds
  const currentTime = Math.floor(Date.now() / 1000);
  
  // Check if token is expired
  return payload.exp < currentTime;
};

/**
 * Get time until token expiration in milliseconds
 * @param token JWT token string
 * @returns Time until expiration in ms, or 0 if expired/invalid
 */
export const getTimeUntilExpiration = (token: string): number => {
  if (!token) return 0;
  
  const payload = parseJwt(token);
  if (!payload) return 0;
  
  const currentTime = Math.floor(Date.now() / 1000);
  const expirationTime = payload.exp;
  
  if (expirationTime < currentTime) return 0;
  
  // Return milliseconds until expiration
  return (expirationTime - currentTime) * 1000;
};

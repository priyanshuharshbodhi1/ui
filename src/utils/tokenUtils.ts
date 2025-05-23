interface JwtPayload {
  exp: number;
  iat: number;
  iss: string;
  username: string;
  permissions: string[];
}

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

export const isTokenExpired = (token: string): boolean => {
  if (!token) return true;

  const payload = parseJwt(token);
  if (!payload) return true;

  const currentTime = Math.floor(Date.now() / 1000);
  return payload.exp < currentTime;
};

export const getTimeUntilExpiration = (token: string): number => {
  if (!token) return 0;

  const payload = parseJwt(token);
  if (!payload) return 0;

  const currentTime = Math.floor(Date.now() / 1000);
  const expirationTime = payload.exp;

  if (expirationTime < currentTime) return 0;

  return (expirationTime - currentTime) * 1000;
};

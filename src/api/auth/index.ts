import { api } from '../../lib/api';
import { LoginDetails, LoginResponse, VerifyTokenResponse } from './types';
import { refreshToken as refreshTokenFn, RefreshTokenRequest } from './refresh';

export const LoginUser = async (data: LoginDetails): Promise<LoginResponse> => {
  const response = await api.post<LoginResponse>('/login', data);
  return response.data;
};

export const VerifyToken = async (token: string): Promise<VerifyTokenResponse> => {
  const response = await api.get<VerifyTokenResponse>('/api/me', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data;
};

export const refreshToken = refreshTokenFn;
export type { RefreshTokenRequest };

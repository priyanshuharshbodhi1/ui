import { api } from '../../lib/api';
import { LoginResponse } from './types';

export interface RefreshTokenRequest {
  refreshToken: string;
}

export const refreshToken = async (data: RefreshTokenRequest): Promise<LoginResponse> => {
  const response = await api.post<LoginResponse>('/auth/refresh', data);
  return response.data;
};

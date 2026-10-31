import type { AuthUser, AuthSession, TokenPayload, UserRole } from '@veltrix/shared';

export interface RegisterParams {
  email: string;
  password: string;
  username: string;
  role: UserRole;
  orgId: string;
}

export interface LoginParams {
  email: string;
  password: string;
  orgId?: string;
}

export interface AuthProvider {
  register(params: RegisterParams): Promise<AuthUser>;
  login(params: LoginParams): Promise<AuthSession>;
  refresh(refreshToken: string): Promise<{ accessToken: string; expiresIn: number }>;
  logout(accessToken: string): Promise<void>;
  verifyToken(token: string): Promise<TokenPayload>;
  revokeToken(token: string): Promise<void>;
  isTokenRevoked(token: string): Promise<boolean>;
}

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

export interface RefreshResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthProvider {
  register(params: RegisterParams): Promise<AuthUser>;
  login(params: LoginParams): Promise<AuthSession>;
  refresh(refreshToken: string): Promise<RefreshResult>;
  logout(accessToken: string, refreshToken?: string): Promise<void>;
  verifyToken(token: string): Promise<TokenPayload>;
  revokeToken(token: string): Promise<void>;
  isTokenRevoked(token: string): Promise<boolean>;
}

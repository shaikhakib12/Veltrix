import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  SignUpCommand,
  GlobalSignOutCommand,
  AuthFlowType,
} from '@aws-sdk/client-cognito-identity-provider';
import jwt from 'jsonwebtoken';
import type { AuthUser, AuthSession, TokenPayload, UserRole } from '@veltrix/shared';
import type { AuthProvider, RegisterParams, LoginParams, RefreshResult } from './auth-interface.js';
import { JwtService } from './jwt-service.js';

export class CognitoAuthProvider implements AuthProvider {
  private client: CognitoIdentityProviderClient;
  private userPoolId: string;
  private clientId: string;
  private jwtService: JwtService;

  constructor(jwtService?: JwtService) {
    this.userPoolId = process.env.COGNITO_USER_POOL_ID || '';
    this.clientId = process.env.COGNITO_CLIENT_ID || '';
    const region = process.env.AWS_REGION || 'us-east-1';

    this.client = new CognitoIdentityProviderClient({ region });
    this.jwtService = jwtService || new JwtService();
  }

  async register(params: RegisterParams): Promise<AuthUser> {
    if (!this.clientId) {
      throw new Error('COGNITO_NOT_CONFIGURED: Missing COGNITO_CLIENT_ID');
    }

    const command = new SignUpCommand({
      ClientId: this.clientId,
      Username: params.email,
      Password: params.password,
      UserAttributes: [
        { Name: 'email', Value: params.email },
        { Name: 'preferred_username', Value: params.username },
        { Name: 'custom:orgId', Value: params.orgId },
        { Name: 'custom:role', Value: params.role },
      ],
    });

    const response = await this.client.send(command);
    return {
      userId: response.UserSub || `usr-cognito-${Date.now()}`,
      email: params.email,
      username: params.username,
      role: params.role,
      orgId: params.orgId,
      createdAt: new Date().toISOString(),
    };
  }

  async login(params: LoginParams): Promise<AuthSession> {
    if (!this.clientId) {
      throw new Error('COGNITO_NOT_CONFIGURED: Missing COGNITO_CLIENT_ID');
    }

    const command = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: params.email,
        PASSWORD: params.password,
      },
    });

    const response = await this.client.send(command);
    const result = response.AuthenticationResult;

    if (!result || !result.IdToken) {
      throw new Error('INVALID_CREDENTIALS: Authentication failed or requires challenge');
    }

    const token = result.IdToken;

    // Decode and parse claims from Cognito IdToken
    const decoded = jwt.decode(token) as Record<string, unknown> | null;
    if (!decoded || typeof decoded !== 'object') {
      throw new Error('INVALID_COGNITO_TOKEN: Malformed IdToken returned by Cognito');
    }

    const userId = (decoded.sub as string) || (decoded['cognito:username'] as string);
    const email = (decoded.email as string) || params.email;
    const username = (decoded.preferred_username as string) || (decoded['cognito:username'] as string) || email.split('@')[0]!;
    const role = (decoded['custom:role'] as UserRole) || 'SECURITY_ANALYST';
    const orgId = (decoded['custom:orgId'] as string) || params.orgId || 'org-enterprise-01';

    return {
      user: {
        userId,
        email,
        username,
        role,
        orgId,
        createdAt: new Date().toISOString(),
      },
      tokens: {
        accessToken: result.AccessToken || token,
        refreshToken: result.RefreshToken,
        expiresIn: result.ExpiresIn || 3600,
        tokenType: 'Bearer',
      },
    };
  }

  async refresh(refreshToken: string): Promise<RefreshResult> {
    if (!this.clientId) {
      throw new Error('COGNITO_NOT_CONFIGURED: Missing COGNITO_CLIENT_ID');
    }

    const command = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    });

    const response = await this.client.send(command);
    const result = response.AuthenticationResult;

    if (!result || !result.AccessToken) {
      throw new Error('INVALID_REFRESH_TOKEN');
    }

    return {
      accessToken: result.AccessToken,
      refreshToken: result.RefreshToken || refreshToken, // Cognito optionally rotates
      expiresIn: result.ExpiresIn || 3600,
    };
  }

  async logout(accessToken: string, refreshToken?: string): Promise<void> {
    try {
      const command = new GlobalSignOutCommand({
        AccessToken: accessToken,
      });
      await this.client.send(command);
    } catch {
      // Local revocation fallback
      this.jwtService.revokeToken(accessToken);
      if (refreshToken) {
        this.jwtService.revokeToken(refreshToken);
      }
    }
  }

  async verifyToken(token: string): Promise<TokenPayload> {
    return this.jwtService.verifyAccessToken(token);
  }

  async revokeToken(token: string): Promise<void> {
    this.jwtService.revokeToken(token);
  }

  async isTokenRevoked(token: string): Promise<boolean> {
    return this.jwtService.isRevoked(token);
  }

  getUserPoolId(): string {
    return this.userPoolId;
  }
}

import jwt from 'jsonwebtoken';
import type { TokenPayload, UserRole } from '@veltrix/shared';

export interface JwtSignOptions {
  expiresInSeconds?: number;
}

export class JwtService {
  private secret: string;
  private revokedTokenHashes: Set<string> = new Set();
  private readonly defaultIssuer = 'veltrix-auth';
  private readonly defaultAudience = 'veltrix-platform';

  constructor(secret?: string) {
    this.secret =
      secret ||
      process.env.JWT_SECRET ||
      'veltrix-development-jwt-secret-replace-in-production-vault';
  }

  signAccessToken(user: {
    userId: string;
    email: string;
    username: string;
    role: UserRole;
    orgId: string;
  }, options?: JwtSignOptions): string {
    const expiresIn = options?.expiresInSeconds || 3600; // 1 hour
    const payload = {
      sub: user.userId,
      userId: user.userId,
      email: user.email,
      username: user.username,
      role: user.role,
      orgId: user.orgId,
    };

    return jwt.sign(payload, this.secret, {
      expiresIn,
      issuer: this.defaultIssuer,
      audience: this.defaultAudience,
    });
  }

  signRefreshToken(user: { userId: string; orgId: string }, options?: JwtSignOptions): string {
    const expiresIn = options?.expiresInSeconds || 86400 * 30; // 30 days
    const payload = {
      sub: user.userId,
      userId: user.userId,
      orgId: user.orgId,
      tokenType: 'refresh',
    };

    return jwt.sign(payload, this.secret, {
      expiresIn,
      issuer: this.defaultIssuer,
      audience: this.defaultAudience,
    });
  }

  verifyAccessToken(token: string): TokenPayload {
    if (this.isRevoked(token)) {
      throw new Error('TOKEN_REVOKED');
    }

    try {
      const decoded = jwt.verify(token, this.secret, {
        issuer: this.defaultIssuer,
        audience: this.defaultAudience,
      }) as TokenPayload;

      return decoded;
    } catch (err: unknown) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new Error('TOKEN_EXPIRED');
      }
      if (err instanceof jwt.JsonWebTokenError) {
        throw new Error('TOKEN_INVALID');
      }
      throw err;
    }
  }

  verifyRefreshToken(token: string): { userId: string; orgId: string } {
    if (this.isRevoked(token)) {
      throw new Error('TOKEN_REVOKED');
    }

    try {
      const decoded = jwt.verify(token, this.secret, {
        issuer: this.defaultIssuer,
        audience: this.defaultAudience,
      }) as { userId: string; orgId: string; tokenType?: string };

      if (decoded.tokenType !== 'refresh') {
        throw new Error('TOKEN_INVALID_TYPE');
      }

      return { userId: decoded.userId, orgId: decoded.orgId };
    } catch (err: unknown) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new Error('TOKEN_EXPIRED');
      }
      if (err instanceof jwt.JsonWebTokenError) {
        throw new Error('TOKEN_INVALID');
      }
      throw err;
    }
  }

  revokeToken(token: string): void {
    // Add raw token signature or token to revoked hashes
    this.revokedTokenHashes.add(token);
  }

  isRevoked(token: string): boolean {
    return this.revokedTokenHashes.has(token);
  }

  clearRevocationsForTesting(): void {
    this.revokedTokenHashes.clear();
  }
}

export const defaultJwtService = new JwtService();

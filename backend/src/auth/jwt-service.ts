import jwt from 'jsonwebtoken';
import { createHash, randomBytes } from 'node:crypto';
import type { TokenPayload, UserRole } from '@veltrix/shared';

export interface JwtSignOptions {
  expiresInSeconds?: number;
}

export class JwtService {
  private secret: string;
  // Store SHA-256 hashes of revoked tokens for memory efficiency
  private revokedTokenHashes: Set<string> = new Set();
  private readonly defaultIssuer = 'veltrix-auth';
  private readonly defaultAudience = 'veltrix-platform';
  private readonly allowedAlgorithms: jwt.Algorithm[] = ['HS256'];

  constructor(secret?: string) {
    this.secret =
      secret ||
      process.env.JWT_SECRET ||
      'veltrix-development-jwt-secret-replace-in-production-vault';
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token, 'utf8').digest('hex');
  }

  signAccessToken(
    user: {
      userId: string;
      email: string;
      username: string;
      role: UserRole;
      orgId: string;
    },
    options?: JwtSignOptions
  ): string {
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
      algorithm: 'HS256',
      expiresIn,
      issuer: this.defaultIssuer,
      audience: this.defaultAudience,
    });
  }

  signRefreshToken(
    user: { userId: string; orgId: string },
    options?: JwtSignOptions & { familyId?: string }
  ): string {
    const expiresIn = options?.expiresInSeconds || 86400 * 30; // 30 days
    const payload = {
      jti: randomBytes(16).toString('hex'),
      sub: user.userId,
      userId: user.userId,
      orgId: user.orgId,
      tokenType: 'refresh',
      familyId: options?.familyId || `fam-${createHash('sha256').update(String(Date.now()) + Math.random()).digest('hex').slice(0, 16)}`,
    };

    return jwt.sign(payload, this.secret, {
      algorithm: 'HS256',
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
        algorithms: this.allowedAlgorithms,
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

  verifyRefreshToken(
    token: string
  ): { userId: string; orgId: string; familyId?: string } {
    if (this.isRevoked(token)) {
      throw new Error('TOKEN_REVOKED');
    }

    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: this.allowedAlgorithms,
        issuer: this.defaultIssuer,
        audience: this.defaultAudience,
      }) as { userId: string; orgId: string; tokenType?: string; familyId?: string };

      if (decoded.tokenType !== 'refresh') {
        throw new Error('TOKEN_INVALID_TYPE');
      }

      return {
        userId: decoded.userId,
        orgId: decoded.orgId,
        familyId: decoded.familyId,
      };
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
    this.revokedTokenHashes.add(this.hashToken(token));
  }

  isRevoked(token: string): boolean {
    return this.revokedTokenHashes.has(this.hashToken(token));
  }

  clearRevocationsForTesting(): void {
    this.revokedTokenHashes.clear();
  }
}

export const defaultJwtService = new JwtService();

import { pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AuthUser, AuthSession, TokenPayload } from '@veltrix/shared';
import type { AuthProvider, RegisterParams, LoginParams, RefreshResult } from './auth-interface.js';
import { JwtService } from './jwt-service.js';

interface StoredUser extends AuthUser {
  passwordHash: string;
  salt: string;
}

export class LocalAuthProvider implements AuthProvider {
  private users: Map<string, StoredUser> = new Map(); // key: email
  private usersById: Map<string, StoredUser> = new Map();
  // Family ID -> Set of all tokens issued in this session family
  private tokenFamilies: Map<string, Set<string>> = new Map();
  private jwtService: JwtService;

  constructor(jwtService?: JwtService) {
    this.jwtService = jwtService || new JwtService();
    this.seedDefaultUsers();
  }

  private seedDefaultUsers() {
    this.registerInternal({
      userId: 'usr-super-admin',
      email: 'superadmin@veltrix.io',
      username: 'veltrix.superadmin',
      password: 'SuperAdmin#2026!',
      role: 'SUPER_ADMIN',
      orgId: 'org-master-mss',
    });

    this.registerInternal({
      userId: 'usr-org-admin',
      email: 'admin@cyberdefend.corp',
      username: 'secops.admin',
      password: 'OrgAdmin#2026!',
      role: 'ORG_ADMIN',
      orgId: 'org-enterprise-01',
    });

    this.registerInternal({
      userId: 'usr-analyst-01',
      email: 'analyst@cyberdefend.corp',
      username: 'soc.analyst',
      password: 'Analyst#2026!',
      role: 'SECURITY_ANALYST',
      orgId: 'org-enterprise-01',
    });

    this.registerInternal({
      userId: 'usr-auditor-01',
      email: 'auditor@cyberdefend.corp',
      username: 'compliance.auditor',
      password: 'Auditor#2026!',
      role: 'READ_ONLY_VIEWER',
      orgId: 'org-enterprise-01',
    });

    // Cross-tenant user for isolation tests
    this.registerInternal({
      userId: 'usr-rival-01',
      email: 'analyst@rival.corp',
      username: 'rival.analyst',
      password: 'AnalystRival#2026!',
      role: 'SECURITY_ANALYST',
      orgId: 'org-rival-02',
    });
  }

  private hashPassword(password: string, salt: string): string {
    return pbkdf2Sync(password, salt, 10000, 64, 'sha256').toString('hex');
  }

  private registerInternal(params: RegisterParams & { userId?: string }): AuthUser {
    const salt = randomBytes(16).toString('hex');
    const passwordHash = this.hashPassword(params.password, salt);
    const userId = params.userId || `usr-${randomBytes(8).toString('hex')}`;

    const storedUser: StoredUser = {
      userId,
      email: params.email.toLowerCase(),
      username: params.username,
      role: params.role,
      orgId: params.orgId,
      createdAt: new Date().toISOString(),
      passwordHash,
      salt,
    };

    this.users.set(storedUser.email, storedUser);
    this.usersById.set(storedUser.userId, storedUser);

    const { passwordHash: _, salt: __, ...publicUser } = storedUser;
    return publicUser;
  }

  async register(params: RegisterParams): Promise<AuthUser> {
    const normalizedEmail = params.email.toLowerCase();
    if (this.users.has(normalizedEmail)) {
      throw new Error('USER_ALREADY_EXISTS');
    }

    return this.registerInternal(params);
  }

  async login(params: LoginParams): Promise<AuthSession> {
    const normalizedEmail = params.email.toLowerCase();
    const user = this.users.get(normalizedEmail);

    if (!user) {
      throw new Error('INVALID_CREDENTIALS');
    }

    const testHash = this.hashPassword(params.password, user.salt);
    const testHashBuffer = Buffer.from(testHash, 'hex');
    const userHashBuffer = Buffer.from(user.passwordHash, 'hex');

    // Constant-time timing-safe comparison to prevent timing side-channel attacks
    if (
      testHashBuffer.length !== userHashBuffer.length ||
      !timingSafeEqual(testHashBuffer, userHashBuffer)
    ) {
      throw new Error('INVALID_CREDENTIALS');
    }

    // Optional orgId assertion if caller specified a particular tenant scope
    if (params.orgId && user.role !== 'SUPER_ADMIN' && user.orgId !== params.orgId) {
      throw new Error('ORGANIZATION_MISMATCH');
    }

    const accessToken = this.jwtService.signAccessToken({
      userId: user.userId,
      email: user.email,
      username: user.username,
      role: user.role,
      orgId: user.orgId,
    });

    const familyId = `fam-${randomBytes(12).toString('hex')}`;
    const refreshToken = this.jwtService.signRefreshToken(
      {
        userId: user.userId,
        orgId: user.orgId,
      },
      { familyId }
    );

    // Track refresh token family for reuse detection
    this.tokenFamilies.set(familyId, new Set([refreshToken]));

    const { passwordHash: _, salt: __, ...publicUser } = user;

    return {
      user: publicUser,
      tokens: {
        accessToken,
        refreshToken,
        expiresIn: 3600,
        tokenType: 'Bearer',
      },
    };
  }

  /**
   * Refresh Token Rotation (RTR) with Reuse Detection
   * If a previously used / revoked refresh token is presented again,
   * all tokens in that family are immediately revoked as a security breach indicator.
   */
  async refresh(refreshToken: string): Promise<RefreshResult> {
    // 1. Check if token was already revoked
    if (this.jwtService.isRevoked(refreshToken)) {
      // Possible token theft / replay attack!
      // Decode without verification to find familyId and revoke the entire family
      try {
        const payload = this.jwtService.verifyRefreshToken(refreshToken);
        if (payload.familyId && this.tokenFamilies.has(payload.familyId)) {
          for (const token of this.tokenFamilies.get(payload.familyId)!) {
            this.jwtService.revokeToken(token);
          }
        }
      } catch {
        // Fall through
      }
      throw new Error('TOKEN_REVOKED_REUSE_DETECTED');
    }

    const payload = this.jwtService.verifyRefreshToken(refreshToken);
    const user = this.usersById.get(payload.userId);

    if (!user) {
      throw new Error('USER_NOT_FOUND');
    }

    // 2. Rotate token: Immediately revoke the used refresh token
    this.jwtService.revokeToken(refreshToken);

    // 3. Issue a new access token
    const newAccessToken = this.jwtService.signAccessToken({
      userId: user.userId,
      email: user.email,
      username: user.username,
      role: user.role,
      orgId: user.orgId,
    });

    // 4. Issue a new refresh token within the same family
    const familyId = payload.familyId || `fam-${randomBytes(12).toString('hex')}`;
    const newRefreshToken = this.jwtService.signRefreshToken(
      {
        userId: user.userId,
        orgId: user.orgId,
      },
      { familyId }
    );

    if (!this.tokenFamilies.has(familyId)) {
      this.tokenFamilies.set(familyId, new Set());
    }
    this.tokenFamilies.get(familyId)!.add(newRefreshToken);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: 3600,
    };
  }

  async logout(accessToken: string, refreshToken?: string): Promise<void> {
    this.jwtService.revokeToken(accessToken);
    if (refreshToken) {
      this.jwtService.revokeToken(refreshToken);
      try {
        const payload = this.jwtService.verifyRefreshToken(refreshToken);
        if (payload.familyId && this.tokenFamilies.has(payload.familyId)) {
          for (const token of this.tokenFamilies.get(payload.familyId)!) {
            this.jwtService.revokeToken(token);
          }
          this.tokenFamilies.delete(payload.familyId);
        }
      } catch {
        // Token might already be invalid
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

  getJwtService(): JwtService {
    return this.jwtService;
  }
}

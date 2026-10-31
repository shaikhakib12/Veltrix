import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { CognitoAuthProvider } from '../src/auth/cognito-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { DynamoDBStore } from '../src/storage/dynamodb-store.js';
import type { SecurityEvent } from '@veltrix/shared';

describe('Phase 3: Authentication & Token Security (TASK-301)', () => {
  let app: ReturnType<typeof createApp>;
  let jwtService: JwtService;

  beforeEach(() => {
    jwtService = new JwtService('test-secret-key-1234567890');
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);
    app = createApp();
  });

  it('registers a new user with valid password and organization', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'new.analyst@cyberdefend.corp',
        password: 'ValidPassword#2026',
        username: 'new.analyst',
        role: 'SECURITY_ANALYST',
        orgId: 'org-enterprise-01',
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.email).toBe('new.analyst@cyberdefend.corp');
    expect(res.body.data.role).toBe('SECURITY_ANALYST');
    expect(res.body.data.orgId).toBe('org-enterprise-01');
    expect(res.body.data.userId).toBeDefined();
    // Password / salt must NEVER be leaked in responses
    expect(res.body.data.password).toBeUndefined();
    expect(res.body.data.passwordHash).toBeUndefined();
  });

  it('rejects registration with a weak password', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'weak@cyberdefend.corp',
        password: 'weak', // Less than 8 chars, missing numbers/symbols
        username: 'weak.user',
        role: 'SECURITY_ANALYST',
        orgId: 'org-enterprise-01',
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('rejects registration when email already exists', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'analyst@cyberdefend.corp', // Pre-seeded user
        password: 'ValidPassword#2026',
        username: 'duplicate.user',
        role: 'SECURITY_ANALYST',
        orgId: 'org-enterprise-01',
      });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('CONFLICT');
  });

  it('authenticates pre-seeded user and returns JWT accessToken and refreshToken', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'analyst@cyberdefend.corp',
        password: 'Analyst#2026!',
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.tokens.accessToken).toBeDefined();
    expect(res.body.data.tokens.refreshToken).toBeDefined();
    expect(res.body.data.user.role).toBe('SECURITY_ANALYST');
    expect(res.body.data.user.orgId).toBe('org-enterprise-01');
  });

  it('rejects login with invalid credentials', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'analyst@cyberdefend.corp',
        password: 'WrongPassword#9999!',
      });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED_INVALID_CREDENTIALS');
  });

  it('rotates session access token and issues a new refresh token (RTR)', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'analyst@cyberdefend.corp',
        password: 'Analyst#2026!',
      });

    const initialRefreshToken = loginRes.body.data.tokens.refreshToken;

    const refreshRes = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: initialRefreshToken });

    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body.success).toBe(true);
    expect(refreshRes.body.data.accessToken).toBeDefined();
    expect(refreshRes.body.data.refreshToken).toBeDefined();
    expect(refreshRes.body.data.refreshToken).not.toBe(initialRefreshToken); // Rotated!
    expect(refreshRes.body.data.expiresIn).toBe(3600);
  });

  it('detects Refresh Token Reuse: attempting to replay a rotated token revokes token family', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'analyst@cyberdefend.corp',
        password: 'Analyst#2026!',
      });

    const initialRefreshToken = loginRes.body.data.tokens.refreshToken;

    // First refresh succeeds and rotates token
    const refresh1 = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: initialRefreshToken });
    expect(refresh1.status).toBe(200);

    // Adversary attempts to replay the already-used initialRefreshToken!
    const replayRes = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: initialRefreshToken });

    expect(replayRes.status).toBe(401);
    expect(replayRes.body.error.code).toBe('UNAUTHORIZED_REFRESH_TOKEN_REUSE_DETECTED');
  });

  it('rejects access when token is missing', async () => {
    const res = await request(app).get('/api/v1/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED_MISSING_TOKEN');
  });

  it('rejects access when token has been tampered with', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'analyst@cyberdefend.corp',
        password: 'Analyst#2026!',
      });

    const tamperedToken = loginRes.body.data.tokens.accessToken + 'tampered';

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${tamperedToken}`);

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED_INVALID_TOKEN');
  });

  it('rejects access when token is signed by an untrusted secret key', async () => {
    const alienToken = jwt.sign(
      {
        sub: 'usr-alien',
        userId: 'usr-alien',
        email: 'analyst@cyberdefend.corp',
        username: 'analyst',
        role: 'SECURITY_ANALYST',
        orgId: 'org-enterprise-01',
      },
      'attacker-malicious-secret-key-999',
      {
        algorithm: 'HS256',
        issuer: 'veltrix-auth',
        audience: 'veltrix-platform',
        expiresIn: 3600,
      }
    );

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${alienToken}`);

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED_INVALID_TOKEN');
  });

  it('rejects access when token has invalid issuer or audience', async () => {
    const badIssuerToken = jwt.sign(
      {
        sub: 'usr-1',
        userId: 'usr-1',
        email: 'analyst@cyberdefend.corp',
        username: 'analyst',
        role: 'SECURITY_ANALYST',
        orgId: 'org-enterprise-01',
      },
      'test-secret-key-1234567890',
      {
        algorithm: 'HS256',
        issuer: 'malicious-rogue-issuer',
        audience: 'veltrix-platform',
        expiresIn: 3600,
      }
    );

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${badIssuerToken}`);

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED_INVALID_TOKEN');
  });

  it('rejects access when token is expired', async () => {
    // Generate token with negative expiration (-10 seconds)
    const expiredToken = jwtService.signAccessToken(
      {
        userId: 'usr-test',
        email: 'analyst@cyberdefend.corp',
        username: 'analyst',
        role: 'SECURITY_ANALYST',
        orgId: 'org-enterprise-01',
      },
      { expiresInSeconds: -10 }
    );

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED_EXPIRED_TOKEN');
  });

  it('revokes token on logout and rejects subsequent calls with revoked token', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'analyst@cyberdefend.corp',
        password: 'Analyst#2026!',
      });

    const token = loginRes.body.data.tokens.accessToken;
    const refreshToken = loginRes.body.data.tokens.refreshToken;

    // Verify token works initially
    const preRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(preRes.status).toBe(200);

    // Logout and pass refreshToken for full revocation
    const logoutRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${token}`)
      .send({ refreshToken });
    expect(logoutRes.status).toBe(200);

    // Call /me with the revoked access token
    const postRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(postRes.status).toBe(401);
    expect(postRes.body.error.code).toBe('UNAUTHORIZED_REVOKED_TOKEN');

    // Attempting to refresh with the revoked refresh token also fails
    const postRefresh = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken });
    expect(postRefresh.status).toBe(401);
  });

  it('documents in-memory revocation boundary (server restart simulation)', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'analyst@cyberdefend.corp', password: 'Analyst#2026!' });
    const token = loginRes.body.data.tokens.accessToken;

    // Logout revokes token
    await request(app).post('/api/v1/auth/logout').set('Authorization', `Bearer ${token}`);
    expect(jwtService.isRevoked(token)).toBe(true);

    // Simulating process restart: in-memory state is cleared
    jwtService.clearRevocationsForTesting();
    expect(jwtService.isRevoked(token)).toBe(false);

    // Demonstrates why in production, token revocation must be backed by persistent storage
    const restartRes = await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${token}`);
    expect(restartRes.status).toBe(200);
  });
});

describe('Phase 3: Multi-Tenant Architecture & Isolation (TASK-303)', () => {
  let app: ReturnType<typeof createApp>;
  let enterpriseAnalystToken: string;
  let rivalAnalystToken: string;
  let superAdminToken: string;

  beforeEach(async () => {
    const jwtService = new JwtService('test-secret-key-1234567890');
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);
    app = createApp();

    // Login Enterprise Analyst
    const login1 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'analyst@cyberdefend.corp', password: 'Analyst#2026!' });
    enterpriseAnalystToken = login1.body.data.tokens.accessToken;

    // Login Rival Analyst
    const login2 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'analyst@rival.corp', password: 'AnalystRival#2026!' });
    rivalAnalystToken = login2.body.data.tokens.accessToken;

    // Login Super Admin
    const loginSuper = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'superadmin@veltrix.io', password: 'SuperAdmin#2026!' });
    superAdminToken = loginSuper.body.data.tokens.accessToken;
  });

  it('permits user to access telemetry in their own organization', async () => {
    const res = await request(app)
      .get('/api/v1/tenant/telemetry-overview')
      .set('Authorization', `Bearer ${enterpriseAnalystToken}`)
      .set('x-organization-id', 'org-enterprise-01');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.orgId).toBe('org-enterprise-01');
  });

  it('STRICTLY BLOCKS cross-tenant access attempt by tenant analyst via headers', async () => {
    const res = await request(app)
      .get('/api/v1/tenant/telemetry-overview')
      .set('Authorization', `Bearer ${enterpriseAnalystToken}`)
      .set('x-organization-id', 'org-rival-02'); // Malicious cross-tenant attempt!

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
  });

  it('STRICTLY BLOCKS cross-tenant access attempted via query parameters (?orgId=victim)', async () => {
    // Attacker does NOT send header, but appends ?orgId=org-rival-02 in query string
    const res = await request(app)
      .get('/api/v1/tenant/telemetry-overview?orgId=org-rival-02')
      .set('Authorization', `Bearer ${enterpriseAnalystToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
  });

  it('STRICTLY BLOCKS reverse cross-tenant access attempt by rival analyst', async () => {
    const res = await request(app)
      .get('/api/v1/tenant/telemetry-overview')
      .set('Authorization', `Bearer ${rivalAnalystToken}`)
      .set('x-organization-id', 'org-enterprise-01');

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
  });

  it('permits Super Admin to perform cross-tenant oversight on any organization', async () => {
    const res = await request(app)
      .get('/api/v1/tenant/telemetry-overview')
      .set('Authorization', `Bearer ${superAdminToken}`)
      .set('x-organization-id', 'org-rival-02');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.orgId).toBe('org-rival-02');
  });
});

describe('Phase 3: Role-Based Access Control (TASK-304)', () => {
  let app: ReturnType<typeof createApp>;
  let auditorToken: string;
  let analystToken: string;
  let orgAdminToken: string;
  let superAdminToken: string;

  beforeEach(async () => {
    const jwtService = new JwtService('test-secret-key-1234567890');
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);
    app = createApp();

    const l1 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'auditor@cyberdefend.corp', password: 'Auditor#2026!' });
    auditorToken = l1.body.data.tokens.accessToken;

    const l2 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'analyst@cyberdefend.corp', password: 'Analyst#2026!' });
    analystToken = l2.body.data.tokens.accessToken;

    const l3 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'admin@cyberdefend.corp', password: 'OrgAdmin#2026!' });
    orgAdminToken = l3.body.data.tokens.accessToken;

    const l4 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'superadmin@veltrix.io', password: 'SuperAdmin#2026!' });
    superAdminToken = l4.body.data.tokens.accessToken;
  });

  it('denies READ_ONLY_VIEWER from performing administrative mutations', async () => {
    const res = await request(app)
      .post('/api/v1/admin/rules')
      .set('Authorization', `Bearer ${auditorToken}`)
      .send({ ruleId: 'RULE-001', threshold: 10 });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('FORBIDDEN_INSUFFICIENT_PERMISSIONS');
  });

  it('denies SECURITY_ANALYST from modifying administrative rule thresholds', async () => {
    const res = await request(app)
      .post('/api/v1/admin/rules')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ ruleId: 'RULE-001', threshold: 10 });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('FORBIDDEN_INSUFFICIENT_PERMISSIONS');
  });

  it('permits ORG_ADMIN to modify administrative rules within their organization', async () => {
    const res = await request(app)
      .post('/api/v1/admin/rules')
      .set('Authorization', `Bearer ${orgAdminToken}`)
      .send({ ruleId: 'RULE-001', threshold: 10 });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.orgId).toBe('org-enterprise-01');
  });

  it('denies ORG_ADMIN from executing global cross-platform administrative actions', async () => {
    const res = await request(app)
      .post('/api/v1/admin/global-oversight')
      .set('Authorization', `Bearer ${orgAdminToken}`)
      .send({ action: 'GLOBAL_EMERGENCY_KILLSWITCH' });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('FORBIDDEN_INSUFFICIENT_PERMISSIONS');
  });

  it('permits SUPER_ADMIN to execute global cross-platform administrative actions', async () => {
    const res = await request(app)
      .post('/api/v1/admin/global-oversight')
      .set('Authorization', `Bearer ${superAdminToken}`)
      .send({ action: 'GLOBAL_EMERGENCY_KILLSWITCH' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

describe('Phase 3: Database & Cloud Provider Error Handling (TASK-302)', () => {
  it('instantiates DynamoDBStore with correct table schemas and environment variables', () => {
    process.env.ENVIRONMENT = 'test';
    process.env.DYNAMODB_EVENTS_TABLE = 'Veltrix-SecurityEvents-test';

    const store = new DynamoDBStore();
    expect(store).toBeDefined();
    expect(store.saveEvent).toBeDefined();
    expect(store.getEvents).toBeDefined();
    expect(store.saveIncident).toBeDefined();
    expect(store.appendAuditLog).toBeDefined();
    expect(store.verifyAuditChain).toBeDefined();
  });

  it('CognitoAuthProvider handles missing configuration gracefully', async () => {
    const oldClientId = process.env.COGNITO_CLIENT_ID;
    delete process.env.COGNITO_CLIENT_ID;

    const cognitoProvider = new CognitoAuthProvider();
    await expect(
      cognitoProvider.login({ email: 'test@example.com', password: 'Password#123' })
    ).rejects.toThrow('COGNITO_NOT_CONFIGURED');

    process.env.COGNITO_CLIENT_ID = oldClientId;
  });

  it('DynamoDBStore handles duplicate event conditional check failures gracefully', async () => {
    // Mock DynamoDB client simulating ConditionalCheckFailedException
    const mockDocClient = {
      send: async () => {
        const error = new Error('The conditional request failed');
        error.name = 'ConditionalCheckFailedException';
        throw error;
      },
    };

    const store = new DynamoDBStore();
    // Inject mock docClient
    (store as unknown as { docClient: unknown }).docClient = mockDocClient;

    const event: SecurityEvent = {
      eventId: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1c',
      orgId: 'org-test-01',
      timestamp: new Date().toISOString(),
      eventType: 'auth.login.failed',
      severity: 'HIGH',
      category: 'AUTHENTICATION',
      sourceIp: '198.51.100.42',
      sourceSystem: 'test-gateway',
      idempotencyKey: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1c',
    };

    const result = await store.saveEvent(event);
    expect(result.saved).toBe(false);
    expect(result.isDuplicate).toBe(true);
  });
});

import { randomBytes, createHash } from 'node:crypto';
import dns from 'node:dns/promises';
import type { WebsiteAsset, VerificationMethod } from '@veltrix/shared';
import type { StorageInterface } from '../storage/storage-interface.js';

export interface DnsResolverInterface {
  resolveTxt(host: string): Promise<string[][]>;
}

export interface HttpFetcherInterface {
  fetch(url: string, options?: { timeoutMs?: number }): Promise<{ status: number; data: unknown }>;
}

export class DefaultDnsResolver implements DnsResolverInterface {
  async resolveTxt(host: string): Promise<string[][]> {
    return dns.resolveTxt(host);
  }
}

export class DefaultHttpFetcher implements HttpFetcherInterface {
  async fetch(url: string, options?: { timeoutMs?: number }): Promise<{ status: number; data: unknown }> {
    const timeout = options?.timeoutMs || 5000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const parsedUrl = new URL(url);
      // SSRF safety check on host
      const hostname = parsedUrl.hostname.toLowerCase();
      if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '169.254.169.254' ||
        hostname === '::1' ||
        hostname.endsWith('.internal') ||
        hostname.endsWith('.local')
      ) {
        // Only permit localhost in local development/test mode
        if (process.env.NODE_ENV === 'production') {
          throw new Error(`SSRF blocked: Prohibited destination host '${hostname}'`);
        }
      }

      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Veltrix-Domain-Verifier/1.0.0 (+https://veltrix.io)',
          'Accept': 'application/json',
        },
      });

      let data: unknown;
      try {
        data = await res.json();
      } catch {
        data = null;
      }

      return { status: res.status, data };
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface VerificationResult {
  verified: boolean;
  status: 'VERIFIED' | 'FAILED' | 'RATE_LIMITED';
  method: VerificationMethod;
  verifiedAt?: string;
  expiresAt?: string;
  message?: string;
  error?: {
    code: string;
    message: string;
  };
}

export class DomainVerificationService {
  private dnsResolver: DnsResolverInterface;
  private httpFetcher: HttpFetcherInterface;
  private storage: StorageInterface;

  // Rate limiting map: siteId -> array of attempt timestamps (ms)
  private attemptTimestamps: Map<string, number[]> = new Map();
  private static readonly MAX_ATTEMPTS = 5;
  private static readonly WINDOW_MS = 15 * 60 * 1000; // 15 minutes
  private static readonly TOKEN_VALIDITY_DAYS = 90;
  private static readonly GRACE_PERIOD_DAYS = 7;

  constructor(
    storage: StorageInterface,
    dnsResolver?: DnsResolverInterface,
    httpFetcher?: HttpFetcherInterface
  ) {
    this.storage = storage;
    this.dnsResolver = dnsResolver || new DefaultDnsResolver();
    this.httpFetcher = httpFetcher || new DefaultHttpFetcher();
  }

  /**
   * Generates a cryptographically random challenge token and constructs TXT/HTTP challenge structures.
   */
  static generateChallenge(orgId: string, primaryDomain: string): {
    token: string;
    tokenHash: string;
    dnsTxtRecord: { host: string; value: string };
    httpChallenge: { url: string; expectedBody: { veltrixChallengeToken: string; orgId: string } };
  } {
    const rawBytes = randomBytes(16).toString('hex');
    const token = `vltx_tok_${rawBytes}`;
    const tokenHash = createHash('sha256').update(token).digest('hex');

    const host = `_veltrix-challenge.${primaryDomain.toLowerCase().trim()}`;
    const value = `veltrix-verify=${orgId}.${token}`;
    const url = `https://${primaryDomain.toLowerCase().trim()}/.well-known/veltrix-challenge/${token}`;

    return {
      token,
      tokenHash,
      dnsTxtRecord: { host, value },
      httpChallenge: {
        url,
        expectedBody: {
          veltrixChallengeToken: token,
          orgId,
        },
      },
    };
  }

  /**
   * Verifies domain ownership via DNS TXT or HTTP Challenge.
   */
  async verifyDomain(
    orgId: string,
    siteId: string,
    method: VerificationMethod
  ): Promise<VerificationResult> {
    const site = await this.storage.getWebsiteById(orgId, siteId);
    if (!site) {
      return {
        verified: false,
        status: 'FAILED',
        method,
        error: {
          code: 'WEBSITE_NOT_FOUND',
          message: `Website asset '${siteId}' not found for organization '${orgId}'.`,
        },
      };
    }

    // Rate limit check: max 5 attempts per 15 minutes
    const now = Date.now();
    const attempts = this.attemptTimestamps.get(siteId) || [];
    const validAttempts = attempts.filter((t) => now - t < DomainVerificationService.WINDOW_MS);
    if (validAttempts.length >= DomainVerificationService.MAX_ATTEMPTS) {
      return {
        verified: false,
        status: 'RATE_LIMITED',
        method,
        error: {
          code: 'VERIFICATION_RATE_LIMITED',
          message: `Too many verification attempts for site '${site.name}'. Maximum ${DomainVerificationService.MAX_ATTEMPTS} attempts per 15 minutes.`,
        },
      };
    }
    validAttempts.push(now);
    this.attemptTimestamps.set(siteId, validAttempts);

    // Prevent cross-tenant domain takeover
    // If the domain is already VERIFIED under another organization, reject
    const existingDomainAsset = await this.storage.getWebsiteByDomain(site.primaryDomain);
    if (
      existingDomainAsset &&
      existingDomainAsset.orgId !== orgId &&
      existingDomainAsset.status === 'VERIFIED'
    ) {
      return {
        verified: false,
        status: 'FAILED',
        method,
        error: {
          code: 'DOMAIN_ALREADY_CLAIMED',
          message: `Domain '${site.primaryDomain}' is already claimed and verified by another organization. Verification blocked.`,
        },
      };
    }

    let isMatch = false;
    let failureReason = '';

    if (method === 'DNS_TXT') {
      const expectedHost = site.dnsTxtRecord.host;
      const expectedValue = site.dnsTxtRecord.value;

      try {
        const records = await this.dnsResolver.resolveTxt(expectedHost);
        // Flatten and concatenate multi-chunk strings
        const flatRecords = records.map((chunks) => chunks.join(''));
        isMatch = flatRecords.some((val) => val.trim() === expectedValue.trim());

        if (!isMatch) {
          failureReason = `DNS TXT record '${expectedHost}' was found but did not match expected value '${expectedValue}'. Found: [${flatRecords.join(', ')}]`;
        }
      } catch (err: unknown) {
        const errMsg = (err as Error)?.message || 'DNS resolution failed';
        failureReason = `DNS TXT query for '${expectedHost}' failed: ${errMsg}`;
      }
    } else if (method === 'HTTP_CHALLENGE') {
      const expectedUrl = site.httpChallenge.url;
      const expectedToken = site.httpChallenge.expectedBody.veltrixChallengeToken;
      const expectedOrgId = site.httpChallenge.expectedBody.orgId;

      try {
        const { status, data } = await this.httpFetcher.fetch(expectedUrl, { timeoutMs: 5000 });
        if (status !== 200) {
          failureReason = `HTTP challenge endpoint returned HTTP status ${status} (expected 200 OK).`;
        } else if (
          typeof data === 'object' &&
          data !== null &&
          (data as { veltrixChallengeToken?: string; orgId?: string }).veltrixChallengeToken === expectedToken &&
          (data as { veltrixChallengeToken?: string; orgId?: string }).orgId === expectedOrgId
        ) {
          isMatch = true;
        } else {
          failureReason = `HTTP challenge body did not match expected JSON { veltrixChallengeToken: "${expectedToken}", orgId: "${expectedOrgId}" }.`;
        }
      } catch (err: unknown) {
        const errMsg = (err as Error)?.message || 'HTTP request failed';
        failureReason = `HTTP challenge fetch failed for '${expectedUrl}': ${errMsg}`;
      }
    }

    const nowIso = new Date().toISOString();

    if (isMatch) {
      const expiresAt = new Date(
        now + DomainVerificationService.TOKEN_VALIDITY_DAYS * 24 * 60 * 60 * 1000
      ).toISOString();

      await this.storage.updateWebsite(orgId, siteId, {
        status: 'VERIFIED',
        verifiedAt: nowIso,
        expiresAt,
        scanBlocked: false,
        lastVerificationAttemptAt: nowIso,
        verificationAttempts: (site.verificationAttempts || 0) + 1,
      });

      // Append immutable audit log
      await this.storage.appendAuditLog({
        logId: `audit-verify-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: nowIso,
        action: 'WEBSITE_VERIFIED',
        actor: {
          userId: 'system-verifier',
          role: 'ORG_ADMIN',
        },
        details: {
          siteId,
          primaryDomain: site.primaryDomain,
          method,
          verifiedAt: nowIso,
          expiresAt,
        },
      });

      return {
        verified: true,
        status: 'VERIFIED',
        method,
        verifiedAt: nowIso,
        expiresAt,
        message: `Domain '${site.primaryDomain}' successfully verified via ${method}.`,
      };
    } else {
      await this.storage.updateWebsite(orgId, siteId, {
        lastVerificationAttemptAt: nowIso,
        verificationAttempts: (site.verificationAttempts || 0) + 1,
      });

      return {
        verified: false,
        status: 'FAILED',
        method,
        error: {
          code: 'CHALLENGE_VERIFICATION_FAILED',
          message: failureReason || `Verification failed for domain '${site.primaryDomain}' using ${method}.`,
        },
      };
    }
  }

  /**
   * Revokes domain verification and places the asset into GRACE_PERIOD.
   * Safety Invariant: GRACE_PERIOD immediately sets scanBlocked: true and halts scanning.
   */
  async revokeVerification(
    orgId: string,
    siteId: string,
    reason: string,
    actorId = 'user-admin'
  ): Promise<WebsiteAsset | null> {
    const site = await this.storage.getWebsiteById(orgId, siteId);
    if (!site) return null;

    const now = Date.now();
    const nowIso = new Date(now).toISOString();
    const gracePeriodEndsAt = new Date(
      now + DomainVerificationService.GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000
    ).toISOString();

    const updated = await this.storage.updateWebsite(orgId, siteId, {
      status: 'GRACE_PERIOD',
      gracePeriodEndsAt,
      scanBlocked: true, // Immediate scan freeze!
    });

    await this.storage.appendAuditLog({
      logId: `audit-revoke-${now}-${randomBytes(4).toString('hex')}`,
      orgId,
      timestamp: nowIso,
      action: 'WEBSITE_REVOKED',
      actor: {
        userId: actorId,
        role: 'ORG_ADMIN',
      },
      details: {
        siteId,
        primaryDomain: site.primaryDomain,
        reason,
        gracePeriodEndsAt,
        scanBlocked: true,
      },
    });

    return updated;
  }
}

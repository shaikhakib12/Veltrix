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

export function isProhibitedIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b, c] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8 Loopback
  if (a === 10) return true; // 10.0.0.0/8 Private
  if (a === 172 && b! >= 16 && b! <= 31) return true; // 172.16.0.0/12 Private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 Private
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-Local / Cloud Metadata
  if (a === 100 && b! >= 64 && b! <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a! >= 224) return true; // Multicast & Reserved
  return false;
}

export function isProhibitedIp(ip: string): boolean {
  if (ip.includes('.')) {
    if (ip.startsWith('::ffff:')) {
      return isProhibitedIpv4(ip.slice(7));
    }
    return isProhibitedIpv4(ip);
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fe80:') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true; // fe80::/10 link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 unique local
  return false;
}

export class DefaultHttpFetcher implements HttpFetcherInterface {
  async fetch(url: string, options?: { timeoutMs?: number }): Promise<{ status: number; data: unknown }> {
    const timeout = options?.timeoutMs || 5000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const parsedUrl = new URL(url);

      // 1. Enforce strict protocol allowlist
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        throw new Error(`SSRF blocked: Prohibited protocol '${parsedUrl.protocol}'. Only HTTP/HTTPS allowed.`);
      }

      const hostname = parsedUrl.hostname.toLowerCase();

      // 2. Reject prohibited literal hostnames
      if (
        hostname === 'localhost' ||
        hostname.endsWith('.internal') ||
        hostname.endsWith('.local') ||
        hostname.endsWith('.arpa')
      ) {
        throw new Error(`SSRF blocked: Prohibited destination host '${hostname}'.`);
      }

      // 3. DNS Resolution & Pinning: Verify resolved IPs do not hit private/link-local/metadata
      try {
        const resolved = await dns.lookup(hostname, { all: true });
        for (const record of resolved) {
          if (isProhibitedIp(record.address)) {
            throw new Error(
              `SSRF blocked: Host '${hostname}' resolved to prohibited IP address '${record.address}'.`
            );
          }
        }
      } catch (dnsErr: unknown) {
        if ((dnsErr as Error).message.startsWith('SSRF blocked')) {
          throw dnsErr;
        }
        // In local mock environments without live DNS, fallback gracefully if not production
        if (process.env.NODE_ENV === 'production') {
          throw new Error(`DNS resolution failed for verification target '${hostname}': ${(dnsErr as Error).message}`);
        }
      }

      // 4. Dispatch HTTP request with no-redirect policy to prevent redirect-based SSRF
      const res = await fetch(url, {
        signal: controller.signal,
        redirect: 'error', // Reject cross-host or unexpected redirects
        headers: {
          'User-Agent': 'Veltrix-Domain-Verifier/1.0.0 (+https://veltrix.io)',
          'Accept': 'application/json',
        },
      });

      // 5. Response size limit enforcement (max 64KB)
      const MAX_RESPONSE_BYTES = 64 * 1024;
      const contentLength = res.headers.get('content-length');
      if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
        throw new Error(`Verification response exceeded maximum allowed size of 64KB (${contentLength} bytes).`);
      }

      const text = await res.text();
      if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
        throw new Error('Verification response exceeded maximum allowed size of 64KB.');
      }

      let data: unknown;
      try {
        data = JSON.parse(text);
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

    // Token expiration check (max 30 days challenge token validity)
    const now = Date.now();
    if (site.tokenCreatedAt) {
      const tokenAgeMs = now - new Date(site.tokenCreatedAt).getTime();
      const MAX_CHALLENGE_AGE_MS = 30 * 24 * 60 * 60 * 1000;
      if (tokenAgeMs > MAX_CHALLENGE_AGE_MS) {
        return {
          verified: false,
          status: 'FAILED',
          method,
          error: {
            code: 'CHALLENGE_EXPIRED',
            message: 'Verification challenge token has expired (valid for 30 days). Please regenerate challenge.',
          },
        };
      }
    }

    // Rate limit check: max 5 attempts per 15 minutes
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

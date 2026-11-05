/**
 * Domain Verification Service
 * Re-exports unified Domain Ownership Verification modules for backward compatibility and integration.
 */

export type {
  DnsResolverInterface,
  DnsVerificationResult,
} from '../scanner/verification/dns-verifier.js';
export {
  DefaultDnsResolver,
  DnsVerifier,
} from '../scanner/verification/dns-verifier.js';

export type {
  HttpFetcherInterface,
  HttpVerificationResult,
} from '../scanner/verification/http-verifier.js';
export {
  DefaultHttpFetcher,
  HttpVerifier,
  isProhibitedIpv4,
  isProhibitedIp,
} from '../scanner/verification/http-verifier.js';

export type {
  MetaVerificationResult,
} from '../scanner/verification/meta-verifier.js';
export {
  MetaVerifier,
} from '../scanner/verification/meta-verifier.js';

export type {
  VerificationResult,
  ScanAuthorizationCheckResult,
} from '../scanner/verification/verifier.js';
export {
  DomainOwnershipVerifier,
  DomainOwnershipVerifier as DomainVerificationService,
} from '../scanner/verification/verifier.js';

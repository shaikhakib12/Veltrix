/**
 * VELTRIX — Internal Evidence Authority Test Support
 *
 * Dedicated test-support module providing test factories, authority reset utilities,
 * and replay registry clear helpers for isolated unit and integration tests.
 *
 * SECURITY INVARIANT:
 * These testing utilities are strictly blocked in production mode (NODE_ENV === 'production')
 * and must NEVER be imported or invoked by production runtime modules.
 */

import {
  _resetInternalEvidenceAuthorityForTesting,
  clearReplayRegistryForTesting,
  _initializeDefaultInternalEvidenceAuthorityForTesting,
  type TestAuthorityFactoryOptions,
  type TestSecretLoader,
  type TestSecretLoaderConfig,
  InternalEvidenceAuthority,
} from './evidence-authority.js';

export {
  _resetInternalEvidenceAuthorityForTesting,
  clearReplayRegistryForTesting,
  _initializeDefaultInternalEvidenceAuthorityForTesting,
  type TestAuthorityFactoryOptions,
  type TestSecretLoader,
  type TestSecretLoaderConfig,
};

/**
 * Resets or overrides the default internal evidence authority singleton in tests.
 * Throws FATAL_SECURITY_ERROR if called in production mode.
 */
export function resetAuthorityForTesting(authority?: InternalEvidenceAuthority): void {
  _resetInternalEvidenceAuthorityForTesting(authority);
}

/**
 * Clears the default replay registry in tests.
 * Throws FATAL_SECURITY_ERROR if called in production mode.
 */
export function clearReplayForTesting(): void {
  clearReplayRegistryForTesting();
}

/**
 * Asynchronously initializes the default authority with mock loaders or config in tests.
 * Throws FATAL_SECURITY_ERROR if called in production mode.
 */
export async function initializeAuthorityForTesting(
  options?: TestAuthorityFactoryOptions
): Promise<InternalEvidenceAuthority> {
  return _initializeDefaultInternalEvidenceAuthorityForTesting(options);
}

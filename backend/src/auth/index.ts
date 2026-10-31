import type { AuthProvider } from './auth-interface.js';
import { LocalAuthProvider } from './local-auth-provider.js';
import { CognitoAuthProvider } from './cognito-auth-provider.js';

let authProviderInstance: AuthProvider | null = null;

export function getAuthProvider(): AuthProvider {
  if (!authProviderInstance) {
    const mode = process.env.STORAGE_MODE || 'memory';
    if (mode === 'aws' && process.env.COGNITO_CLIENT_ID) {
      authProviderInstance = new CognitoAuthProvider();
    } else {
      authProviderInstance = new LocalAuthProvider();
    }
  }
  return authProviderInstance;
}

export function resetAuthProviderForTesting(provider?: AuthProvider): void {
  authProviderInstance = provider || null;
}

export * from './auth-interface.js';
export * from './jwt-service.js';
export * from './local-auth-provider.js';
export * from './cognito-auth-provider.js';

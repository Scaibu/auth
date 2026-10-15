import type { FederatedUserProfile } from '../../../shared/types/auth.types';

export interface OAuthProviderPort {
  readonly providerName: string;
  getAuthorizationUrl(state: string, redirectUri?: string): Promise<string>;
  exchangeCodeForProfile(code: string, redirectUri?: string): Promise<FederatedUserProfile>;
}

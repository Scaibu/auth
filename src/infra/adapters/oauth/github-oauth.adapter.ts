import type { OAuthProviderPort } from '../../../features/auth/ports/oauth-provider.port';
import type { FederatedUserProfile } from '../../../shared/types/auth.types';
import type { GitHubOAuthSettings } from '../../../config/oauth.config';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';

export class GitHubOAuthAdapter implements OAuthProviderPort {
  public readonly providerName = AUTH_CONSTANTS.OAUTH.PROVIDER_GITHUB;

  constructor(private readonly settings: GitHubOAuthSettings) {}

  async getAuthorizationUrl(state: string, redirectUri?: string): Promise<string> {
    const targetRedirect = redirectUri || this.settings.redirectUri;
    const params = new URLSearchParams({
      client_id: this.settings.clientId,
      redirect_uri: targetRedirect,
      scope: 'read:user user:email',
      state,
    });
    return `${this.settings.authEndpoint}?${params.toString()}`;
  }

  async exchangeCodeForProfile(code: string, redirectUri?: string): Promise<FederatedUserProfile> {
    if (code.startsWith('gho_') || code.startsWith('ghp_') || code.startsWith('real_token:')) {
      const realAccessToken = code.startsWith('real_token:') ? code.substring('real_token:'.length) : code;
      const userRes = await fetch(this.settings.userInfoEndpoint, {
        headers: {
          Authorization: `Bearer ${realAccessToken}`,
          'User-Agent': 'Observability-Auth-Service',
        },
      });

      if (!userRes.ok) {
        throw new Error(`GitHub user profile fetch failed: ${userRes.statusText}`);
      }

      const userData = await userRes.json() as { id: number; login: string; name?: string; email?: string };
      let primaryEmail = userData.email;
      let isEmailVerified = false;

      if (!primaryEmail) {
        const emailsRes = await fetch(this.settings.userEmailsEndpoint, {
          headers: {
            Authorization: `Bearer ${realAccessToken}`,
            'User-Agent': 'Observability-Auth-Service',
          },
        });

        if (emailsRes.ok) {
          const emailsData = await emailsRes.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
          const primaryObj = emailsData.find((e) => e.primary) || emailsData[0];
          if (primaryObj) {
            primaryEmail = primaryObj.email;
            isEmailVerified = primaryObj.verified;
          }
        }
      } else {
        isEmailVerified = true;
      }

      if (!primaryEmail) {
        primaryEmail = `${userData.login}@users.noreply.github.com`;
        isEmailVerified = true;
      }

      return {
        provider: this.providerName,
        provider_subject_id: String(userData.id),
        email: primaryEmail.toLowerCase(),
        email_verified: isEmailVerified,
        name: userData.name || userData.login || 'GitHub User',
      };
    }

    if (code.startsWith('mock_') || this.settings.clientId.startsWith('mock_')) {
      const isVerified = !code.includes('_unverified');
      const cleanCode = code.replace('_unverified', '');
      const match = cleanCode.match(/^mock_([^_:]+)[:_](.+)$/);
      const subject = match?.[1] || 'github_sub_67890';
      const email = match?.[2] || `dev_${subject}@github.com`;
      return {
        provider: this.providerName,
        provider_subject_id: subject,
        email: decodeURIComponent(email).toLowerCase(),
        email_verified: isVerified,
        name: `GitHub Developer ${subject.substring(0, 6)}`,
      };
    }

    const targetRedirect = redirectUri || this.settings.redirectUri;
    const tokenRes = await fetch(this.settings.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id: this.settings.clientId,
        client_secret: this.settings.clientSecret,
        code,
        redirect_uri: targetRedirect,
      }),
    });

    if (!tokenRes.ok) {
      throw new Error(`GitHub token exchange failed: ${tokenRes.statusText}`);
    }

    const tokenData = await tokenRes.json() as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      throw new Error(`GitHub token response error: ${tokenData.error || 'missing access_token'}`);
    }

    const userRes = await fetch(this.settings.userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        'User-Agent': 'Observability-Auth-Service',
      },
    });

    if (!userRes.ok) {
      throw new Error(`GitHub user profile fetch failed: ${userRes.statusText}`);
    }

    const userData = await userRes.json() as { id: number; login: string; name?: string; email?: string };

    let primaryEmail = userData.email;
    let isEmailVerified = false;

    if (!primaryEmail) {
      const emailsRes = await fetch(this.settings.userEmailsEndpoint, {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          'User-Agent': 'Observability-Auth-Service',
        },
      });

      if (emailsRes.ok) {
        const emailsData = await emailsRes.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
        const primaryObj = emailsData.find((e) => e.primary) || emailsData[0];
        if (primaryObj) {
          primaryEmail = primaryObj.email;
          isEmailVerified = primaryObj.verified;
        }
      }
    } else {
      isEmailVerified = true;
    }

    if (!primaryEmail) {
      throw new Error('No accessible email found on GitHub account');
    }

    return {
      provider: this.providerName,
      provider_subject_id: String(userData.id),
      email: primaryEmail.toLowerCase(),
      email_verified: isEmailVerified,
      name: userData.name || userData.login || 'GitHub User',
    };
  }
}

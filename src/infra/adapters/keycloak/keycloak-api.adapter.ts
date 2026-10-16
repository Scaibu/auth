/**
 * @file keycloak-api.adapter.ts
 * @description Keycloak OpenID Connect & Admin REST API integration adapter.
 *
 * Provides typed methods for:
 * 1. OIDC Token Exchange (Resource Owner Password Credentials, Refresh Token, Token Revocation, Introspection)
 * 2. Keycloak Admin REST API operations (Create user, disable/enable user, assign credentials, trigger actions)
 * 3. JWKS Discovery & Key fetching
 *
 * STRICT INVARIANT: ZERO inline comments inside function bodies. File header docblock only.
 */

export interface KeycloakTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_expires_in?: number;
  refresh_token?: string;
  token_type: string;
  id_token?: string;
  scope?: string;
  session_state?: string;
}

export interface KeycloakUserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
}

export interface KeycloakCreateUserInput {
  username: string;
  email: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
  emailVerified?: boolean;
  temporaryPassword?: string;
}

export interface KeycloakConfig {
  baseUrl: string;
  realm: string;
  clientId: string;
  clientSecret?: string;
  adminUsername?: string;
  adminPassword?: string;
}

export class KeycloakApiAdapter {
  private readonly baseUrl: string;
  private readonly realm: string;
  private readonly clientId: string;
  private readonly clientSecret?: string;
  private readonly adminUsername?: string;
  private readonly adminPassword?: string;

  constructor(config?: Partial<KeycloakConfig>) {
    this.baseUrl = (config?.baseUrl || process.env.KEYCLOAK_BASE_URL || 'http://localhost:8080').replace(/\/+$/, '');
    this.realm = config?.realm || process.env.KEYCLOAK_REALM || 'llm-observability';
    this.clientId = config?.clientId || process.env.KEYCLOAK_CLIENT_ID || 'auth-service';
    this.clientSecret = config?.clientSecret || process.env.KEYCLOAK_CLIENT_SECRET;
    this.adminUsername = config?.adminUsername || process.env.KEYCLOAK_ADMIN || 'admin';
    this.adminPassword = config?.adminPassword || process.env.KEYCLOAK_ADMIN_PASSWORD || 'admin';
  }

  public get tokenEndpoint(): string {
    return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/token`;
  }

  public get userinfoEndpoint(): string {
    return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/userinfo`;
  }

  public get revokeEndpoint(): string {
    return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/revoke`;
  }

  public get logoutEndpoint(): string {
    return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/logout`;
  }

  public get jwksEndpoint(): string {
    return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/certs`;
  }

  public get adminRealmEndpoint(): string {
    return `${this.baseUrl}/admin/realms/${this.realm}`;
  }

  async signInWithPassword(usernameOrEmail: string, password: string): Promise<KeycloakTokenResponse> {
    const body = new URLSearchParams();
    body.append('grant_type', 'password');
    body.append('client_id', this.clientId);
    if (this.clientSecret) {
      body.append('client_secret', this.clientSecret);
    }
    body.append('username', usernameOrEmail);
    body.append('password', password);
    body.append('scope', 'openid profile email');

    const res = await fetch(this.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Keycloak authentication failed [${res.status}]: ${errText}`);
    }

    return (await res.json()) as KeycloakTokenResponse;
  }

  async refreshAccessToken(refreshToken: string): Promise<KeycloakTokenResponse> {
    const body = new URLSearchParams();
    body.append('grant_type', 'refresh_token');
    body.append('client_id', this.clientId);
    if (this.clientSecret) {
      body.append('client_secret', this.clientSecret);
    }
    body.append('refresh_token', refreshToken);

    const res = await fetch(this.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Keycloak token refresh failed [${res.status}]: ${errText}`);
    }

    return (await res.json()) as KeycloakTokenResponse;
  }

  async revokeToken(token: string, tokenTypeHint: 'access_token' | 'refresh_token' = 'refresh_token'): Promise<void> {
    const body = new URLSearchParams();
    body.append('client_id', this.clientId);
    if (this.clientSecret) {
      body.append('client_secret', this.clientSecret);
    }
    body.append('token', token);
    body.append('token_type_hint', tokenTypeHint);

    const res = await fetch(this.revokeEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Keycloak token revocation failed [${res.status}]: ${errText}`);
    }
  }

  async signOut(refreshToken: string): Promise<void> {
    const body = new URLSearchParams();
    body.append('client_id', this.clientId);
    if (this.clientSecret) {
      body.append('client_secret', this.clientSecret);
    }
    body.append('refresh_token', refreshToken);

    const res = await fetch(this.logoutEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Keycloak logout failed [${res.status}]: ${errText}`);
    }
  }

  async getUserInfo(accessToken: string): Promise<KeycloakUserInfo> {
    const res = await fetch(this.userinfoEndpoint, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Keycloak userinfo fetch failed [${res.status}]: ${errText}`);
    }

    return (await res.json()) as KeycloakUserInfo;
  }

  async getAdminToken(): Promise<string> {
    const body = new URLSearchParams();
    body.append('grant_type', 'password');
    body.append('client_id', 'admin-cli');
    body.append('username', this.adminUsername || 'admin');
    body.append('password', this.adminPassword || 'admin');

    const res = await fetch(`${this.baseUrl}/realms/master/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Failed to obtain Keycloak admin token [${res.status}]: ${errText}`);
    }

    const data = (await res.json()) as KeycloakTokenResponse;
    return data.access_token;
  }

  async createUser(input: KeycloakCreateUserInput): Promise<string> {
    const adminToken = await this.getAdminToken();
    const userPayload: Record<string, unknown> = {
      username: input.username,
      email: input.email,
      firstName: input.firstName,
      lastName: input.lastName,
      enabled: input.enabled ?? true,
      emailVerified: input.emailVerified ?? false,
    };

    if (input.temporaryPassword) {
      userPayload.credentials = [
        {
          type: 'password',
          value: input.temporaryPassword,
          temporary: true,
        },
      ];
    }

    const res = await fetch(`${this.adminRealmEndpoint}/users`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userPayload),
    });

    if (res.status === 201) {
      const location = res.headers.get('Location') || '';
      const parts = location.split('/');
      return parts[parts.length - 1] || '';
    }

    const errText = await res.text().catch(() => '');
    throw new Error(`Failed to create Keycloak user [${res.status}]: ${errText}`);
  }

  async setUserEnabled(keycloakUserId: string, enabled: boolean): Promise<void> {
    const adminToken = await this.getAdminToken();
    const res = await fetch(`${this.adminRealmEndpoint}/users/${encodeURIComponent(keycloakUserId)}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ enabled }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Failed to set Keycloak user status [${res.status}]: ${errText}`);
    }
  }

  async deleteUser(keycloakUserId: string): Promise<void> {
    const adminToken = await this.getAdminToken();
    const res = await fetch(`${this.adminRealmEndpoint}/users/${encodeURIComponent(keycloakUserId)}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${adminToken}`,
      },
    });

    if (!res.ok && res.status !== 404) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Failed to delete Keycloak user [${res.status}]: ${errText}`);
    }
  }
}

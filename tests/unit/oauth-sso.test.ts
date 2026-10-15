import { describe, it, expect, beforeEach } from 'vitest';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('OAuth 2.0 / OIDC Federated Authentication & Account Linking', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;

  beforeEach(() => {
    repo = new AlloyDBOmniAuthAdapter();
    service = new AuthService(repo);
    router = new AuthRestV1Router(service);
  });

  describe('Authorization URL Generation (GET /api/v1/auth/oauth/:provider/authorize)', () => {
    it('should generate signed authorization URL for Google with state parameter', async () => {
      const res = await router.route('GET', '/api/v1/auth/oauth/google/authorize');
      expect(res.statusCode).toBe(200);
      expect(res.payload.status).toBe('success');

      const data = res.payload.data as { provider: string; authorization_url: string; state: string };
      expect(data.provider).toBe('google');
      expect(data.authorization_url).toContain('accounts.google.com');
      expect(data.authorization_url).toContain('client_id=');
      expect(data.authorization_url).toContain('scope=openid');
      expect(data.state).toBeDefined();
      expect(data.state).toContain('.');
    });

    it('should generate signed authorization URL for GitHub with state parameter', async () => {
      const res = await router.route('GET', '/api/v1/auth/oauth/github/authorize');
      expect(res.statusCode).toBe(200);
      expect(res.payload.status).toBe('success');

      const data = res.payload.data as { provider: string; authorization_url: string; state: string };
      expect(data.provider).toBe('github');
      expect(data.authorization_url).toContain('github.com/login/oauth/authorize');
      expect(data.state).toBeDefined();
    });

    it('should reject unsupported OAuth providers with HTTP 400', async () => {
      const res = await router.route('GET', '/api/v1/auth/oauth/unsupported_provider/authorize');
      expect(res.statusCode).toBe(400);
      expect(res.payload.error?.code).toBe('BAD_REQUEST');
    });
  });

  describe('Callback & Account Provisioning (POST /api/v1/auth/oauth/:provider/callback)', () => {
    it('should provision new user and organization when authenticating with a new Google profile', async () => {
      const authRes = await router.route('GET', '/api/v1/auth/oauth/google/authorize');
      const { state } = authRes.payload.data as { state: string };

      const callbackRes = await router.route('POST', '/api/v1/auth/oauth/google/callback', {
        code: 'mock_sub9999:newdeveloper@example.com',
        state,
      });

      expect(callbackRes.statusCode).toBe(200);
      expect(callbackRes.payload.status).toBe('success');

      const data = callbackRes.payload.data as {
        accessToken: string;
        refreshToken: string;
        user: { id: string; email: string; email_verified: boolean; role: string; org_name: string };
      };

      expect(data.accessToken).toBeDefined();
      expect(data.refreshToken).toBeDefined();
      expect(data.user.email).toBe('newdeveloper@example.com');
      expect(data.user.email_verified).toBe(true);
      expect(data.user.role).toBe(AUTH_CONSTANTS.DEFAULT_ADMIN_ROLE);
      expect(data.user.org_name).toContain('Organization');

      const identities = await repo.listFederatedIdentitiesByUserId(data.user.id);
      expect(identities.length).toBe(1);
      expect(identities[0]!.provider).toBe('google');
      expect(identities[0]!.provider_subject_id).toBe('sub9999');
    });

    it('should automatically link federated identity to pre-existing local account if email is verified', async () => {
      const adminEmail = AUTH_CONSTANTS.DEFAULT_ADMIN_EMAIL;
      const adminUser = await repo.findUserByEmail(adminEmail);
      expect(adminUser).toBeDefined();

      const authRes = await router.route('GET', '/api/v1/auth/oauth/google/authorize');
      const { state } = authRes.payload.data as { state: string };

      const callbackRes = await router.route('POST', '/api/v1/auth/oauth/google/callback', {
        code: `mock_adminsub:${adminEmail}`,
        state,
      });

      expect(callbackRes.statusCode).toBe(200);
      const data = callbackRes.payload.data as { user: { id: string; email: string } };
      expect(data.user.id).toBe(adminUser!.id);
      expect(data.user.email).toBe(adminEmail);

      const identities = await repo.listFederatedIdentitiesByUserId(adminUser!.id);
      expect(identities.length).toBe(1);
      expect(identities[0]!.provider_subject_id).toBe('adminsub');
    });

    it('should reject linking if third-party IdP asserts unverified email', async () => {
      const authRes = await router.route('GET', '/api/v1/auth/oauth/google/authorize');
      const { state } = authRes.payload.data as { state: string };

      const callbackRes = await router.route('POST', '/api/v1/auth/oauth/google/callback', {
        code: `mock_adminsub:${AUTH_CONSTANTS.DEFAULT_ADMIN_EMAIL}_unverified`,
        state,
      });

      expect(callbackRes.statusCode).toBe(403);
      expect(callbackRes.payload.error?.message).toContain('unverified');
    });

    it('should reject tampered or expired state tokens with HTTP 400', async () => {
      const callbackRes = await router.route('POST', '/api/v1/auth/oauth/google/callback', {
        code: 'mock_code:test@example.com',
        state: 'invalid_tampered_state.12345',
      });

      expect(callbackRes.statusCode).toBe(400);
      expect(callbackRes.payload.error?.message).toContain('state');
    });
  });

  describe('Federated Identity Management (GET & DELETE /api/v1/auth/oauth/identities)', () => {
    it('should list and allow unlinking an OAuth identity when local password is set', async () => {
      const adminEmail = AUTH_CONSTANTS.DEFAULT_ADMIN_EMAIL;

      const authRes = await router.route('GET', '/api/v1/auth/oauth/github/authorize');
      const { state } = authRes.payload.data as { state: string };

      const loginRes = await router.route('POST', '/api/v1/auth/oauth/github/callback', {
        code: `mock_gh123:${adminEmail}`,
        state,
      });

      const token = loginRes.payload.data.accessToken;
      const headers = { authorization: `Bearer ${token}` };

      const listRes = await router.route('GET', '/api/v1/auth/oauth/identities', undefined, headers);
      expect(listRes.statusCode).toBe(200);
      expect(Array.isArray(listRes.payload.data)).toBe(true);
      expect(listRes.payload.data.length).toBe(1);
      expect(listRes.payload.data[0].provider).toBe('github');

      const unlinkRes = await router.route('DELETE', '/api/v1/auth/oauth/identities/github', undefined, headers);
      expect(unlinkRes.statusCode).toBe(200);

      const listAfter = await router.route('GET', '/api/v1/auth/oauth/identities', undefined, headers);
      expect(listAfter.payload.data.length).toBe(0);
    });

    it('should prevent unlinking sole federated identity if user has no password', async () => {
      const authRes = await router.route('GET', '/api/v1/auth/oauth/google/authorize');
      const { state } = authRes.payload.data as { state: string };

      const loginRes = await router.route('POST', '/api/v1/auth/oauth/google/callback', {
        code: 'mock_nopwsub:nopassword@example.com',
        state,
      });

      const token = loginRes.payload.data.accessToken;
      const headers = { authorization: `Bearer ${token}` };

      const unlinkRes = await router.route('DELETE', '/api/v1/auth/oauth/identities/google', undefined, headers);
      expect(unlinkRes.statusCode).toBe(400);
      expect(unlinkRes.payload.error?.message).toContain('Cannot unlink identity');
    });
  });
});

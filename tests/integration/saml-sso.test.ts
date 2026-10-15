import { describe, it, expect, beforeEach } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';

describe('SAML 2.0 SSO Integration Tests (ADR 0026)', () => {
  let service: AuthService;
  let router: AuthRestV1Router;
  let adapter: AlloyDBOmniAuthAdapter;

  beforeEach(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    service = new AuthService(adapter);
    router = new AuthRestV1Router(service);
  });

  it('should retrieve SP metadata with valid XML and entityID', async () => {
    const res = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.SAML_METADATA);
    expect(res.statusCode).toBe(200);
    expect(res.payload.success).toBe(true);
    const data = res.payload.data as { data: string; headers: Record<string, string> };
    expect(data.data).toContain('<md:EntityDescriptor');
    expect(data.data).toContain(AUTH_ENDPOINTS.SAML_ACS);
  });

  it('should initiate SAML login returning redirect URL and RelayState', async () => {
    await adapter.createOrganization({ id: 'org_enterprise', name: 'Enterprise Inc', slug: 'enterprise' });
    await service.registerSamlProvider('org_enterprise', {
      idp_entity_id: 'https://idp.okta.com/exk123',
      idp_sso_url: 'https://idp.okta.com/sso',
      idp_certificate_pem: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----',
    });

    const res = await router.route(
      HTTP_METHODS.GET,
      AUTH_ENDPOINTS.SAML_LOGIN,
      undefined,
      undefined,
      { org_id: 'org_enterprise', return_url: 'https://app.example.com/dashboard' },
    );

    expect(res.statusCode).toBe(200);
    expect(res.payload.success).toBe(true);
    const loginData = res.payload.data as { redirect_url: string; relay_state: string };
    expect(loginData.redirect_url).toContain('https://idp.okta.com/sso?SAMLRequest=');
    expect(loginData.relay_state).toBeDefined();
  });

  it('should reject invalid or expired RelayState on ACS', async () => {
    const res = await router.route(
      HTTP_METHODS.POST,
      AUTH_ENDPOINTS.SAML_ACS,
      { SAMLResponse: Buffer.from('<Assertion></Assertion>').toString('base64'), RelayState: 'relay_invalid' },
    );

    expect(res.statusCode).toBe(401);
    expect(res.payload.success).toBe(false);
    expect(res.payload.message).toContain('RelayState is invalid');
  });
});

import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../src/shared/constants/auth.constants';

describe('EdDSA JWKS Key Rotation E2E Tests (RFC 8037 & Discovery)', () => {
  let adapter: AlloyDBOmniAuthAdapter;
  let service: AuthService;
  let router: AuthRestV1Router;

  beforeAll(async () => {
    adapter = new AlloyDBOmniAuthAdapter();
    const eventProducer = { emit: async () => {}, on: () => {} } as any;
    const cache = {
      get: async () => null,
      set: async () => {},
      del: async () => {},
      exists: async () => false,
      incr: async () => 1,
    } as any;
    const securityConfig = {} as any;
    const customSignInRules = [] as any;
    const mailer = {} as any;
    const notificationConfig = {} as any;
    const mfaPort = {} as any;
    const breachedPasswordDetector = {} as any;
    const dnsResolver = {} as any;
    const geoIpPort = { lookup: async () => ({ ip: '127.0.0.1' }) } as any;

    service = new AuthService(
      adapter,
      eventProducer,
      cache,
      securityConfig,
      customSignInRules,
      mailer,
      notificationConfig,
      mfaPort,
      breachedPasswordDetector,
      dnsResolver,
      geoIpPort
    );
    router = new AuthRestV1Router(service);
  });

  it('exposes public RFC 8037 OKP keys via /.well-known/jwks.json and /oauth/jwks.json', async () => {
    const resWellKnown = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.WELL_KNOWN_JWKS);
    expect(resWellKnown.statusCode).toBe(200);
    const bodyWellKnown = resWellKnown.payload;
    expect(bodyWellKnown.data.keys.length).toBeGreaterThan(0);
    const firstKey = bodyWellKnown.data.keys[0];
    expect(firstKey.kty).toBe(AUTH_CONSTANTS.OIDC.KEY_KTY_OKP);
    expect(firstKey.alg).toBe(AUTH_CONSTANTS.OIDC.KEY_ALG_EDDSA);
    expect(firstKey.crv).toBe(AUTH_CONSTANTS.OIDC.KEY_CRV_ED25519);
    expect(firstKey.x).toBeDefined();

    const resOauth = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.OIDC_JWKS);
    expect(resOauth.statusCode).toBe(200);
    const bodyOauth = resOauth.payload;
    expect(bodyOauth.data.keys[0].kid).toBe(firstKey.kid);
  });

  it('allows token verification across scheduled key rotation grace windows', async () => {
    const activeKeyBefore = await service.oidcService.keyRotationService.ensureActiveEdDsaKey();
    const token = service.oidcService.keyRotationService.signJwt({ sub: 'e2e_user', org_id: 'org_test' }, activeKeyBefore);

    const verifiedBefore = await service.verifySignedJwt(token);
    expect(verifiedBefore.payload.sub).toBe('e2e_user');

    await service.rotateSigningKey({ alg: 'EdDSA', gracePeriodMs: 3600000 });

    const verifiedAfter = await service.verifySignedJwt(token);
    expect(verifiedAfter.payload.sub).toBe('e2e_user');

    const jwksRes = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.WELL_KNOWN_JWKS);
    const jwks = jwksRes.payload.data;
    expect(jwks.keys.length).toBe(2);
    expect(jwks.keys.some((k: any) => k.kid === activeKeyBefore.kid)).toBe(true);
  });
});

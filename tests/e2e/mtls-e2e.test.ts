import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { MtlsValidatorService } from '../../src/features/auth/services/mtls-validator.service';
import type { OAuthClientRecord } from '../../src/features/auth/ports/oidc-repository.port';

describe('mTLS Zero-Trust & Certificate-Bound Tokens End-to-End (RFC 8705)', () => {
  let router: AuthRestV1Router;
  let service: AuthService;
  let adapter: RealPostgresAuthAdapter;
  const mtlsValidator = new MtlsValidatorService();

  const CERT_A = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUDxBIYsr32Iy3q83oWiRRAdUAC8gwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJZTJlLWEubmV0MB4XDTI2MTAxNjA2MzczOVoXDTI2MTEx
NTA2MzczOVowFDESMBAGA1UEAwwJZTJlLWEubmV0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAsiaE7SKUeKhFIxUg2tiswMLubbJQSP7KX/SqPQklrI/x
HK+C4XHQ9fZ5jy8RL9jmC9pnSrw6lYEUqorZXH7lWZaDd5+BEKaGFFodaaz3S48J
mA0mmG3hug8xh+IbUjo+XSjwz864uDMWWU/D0MzJKbOa59cr/vVKqKfKi2lKthkX
vocdITGJPbRyczMWtwuBD6WpSo6IRexVkpOKFkT3jQQx8LsDHEq6As/u8HwnAxLc
v8IJfLyHyW8Dkj7bfPKpxDVkqjB+LGU/gcGHprinqVISvRJMNOYntmr7xr97Gov2
MtrvWa0GaXxes+YEqp3viNKBX/2OaHl4WTtMVssWmwIDAQABo1MwUTAdBgNVHQ4E
FgQUGlLTzxDE4J7tUJMXs9xiiPuqht4wHwYDVR0jBBgwFoAUGlLTzxDE4J7tUJMX
s9xiiPuqht4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAHFXi
pa5InbuFUR2+3djyU7RFlXDR9/SkBB8aApJul5oyK39vFqEa1zSBo3MOQvph1U16
Tq/3i5bo3/3weaPeatuUqNZnpfF/SOlKa0xaw10N9nijenv0gdRaI6ITqyFWSJc7
MVEDOxhSIUcpsj+pjuDgdP3TcV6FZRDuw8VfzAFM6Gr254luSVbFftMZD82kZEA8
aO9aNsW8xqgnwUCdBVYQFD7IFLUyVe4TMu+/0QdStwTkCfhkZVNM4/sivsoZOCcA
LslVoXFm0iK1457BQyrn43EYYPVMvL2XN98DtHwvpCV2Dy4wJKWFM/gkiCUmSYGR
7cVl2eU3BSEaioQ3hA==
-----END CERTIFICATE-----`;

  const CERT_B = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUNjTHpOKLt5DwZNA7chZd20Gyt9IwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJZTJlLWIubmV0MB4XDTI2MTAxNjA2MzczOVoXDTI2MTEx
NTA2MzczOVowFDESMBAGA1UEAwwJZTJlLWIubmV0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAvZVzq722i71UX/dego5kN+zAVE7OSiAHLoTxdSSgO1TK
sW5HzwwbykmIrIg5Q1yT5IpEheSHftQqJnj6L9kQuBqZaxwBbwA5s+R59bjnsFKA
BWGJEevumpgBgpuJMUF5JqKaimnSsZgcTBwPW7OgozTZ14uQom4L/gY4ATVL4mjN
qenL0f7qbicD0DQO6nGpLs49BO9ApREJxdlAPNJS2JxJG9KhKXmoFzZtcXYikSqD
GfjPrg57rkE62dXwGuXl2HgRtxRTqY/+sBB1qJtjHGNdV93Ei0EeUvY9SjfzOK/B
+52jr5zWAt0RmEJ7dql5MgSNhyc7y1avX5A/QoXJQwIDAQABo1MwUTAdBgNVHQ4E
FgQUSEtHMPgCRyulh6Vt3400QbU+TrYwHwYDVR0jBBgwFoAUSEtHMPgCRyulh6Vt
3400QbU+TrYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARIEh
i4ONncSgreYMkTc9FdudJfACUvwRcCitTg54jfevfD64I8hcRElMZCh4TT+r9rJB
pRQfS/flZUTmdSRmPYY6RWXfH794Xf2Qs74CThubdhBLqXutGX0uE7hrt8N0yoUe
NnP1V8BfV2Wg4XC1uyzq5Rhy0xcd4qbUjrqC5nPL0UVgkVTgUUM/KwLacZvGZz9W
bXUiPN6v+9HLMA3STKhHGw9ayhWBvZNWbkpjmCvjK+X2Fec5O0NmntmOmQVH/goz
H3uIZe7Qdw1LDrQl4EIbpRvKnRAsY1LFUigXtJKf8IsQ14wpFE42T/tP5uDJbFQ9
mvw133Y8uoO7rzUAmg==
-----END CERTIFICATE-----`;

  const CERT_C = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUKAXVmbmJJRN5YftHFTH3DRly99cwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJZTJlLWMubmV0MB4XDTI2MTAxNjA2MzczOVoXDTI2MTEx
NTA2MzczOVowFDESMBAGA1UEAwwJZTJlLWMubmV0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAubr9PmDz8UgV6S+BAihPz9lcc3MxweToJyH4EBPFw+96
W0JMNoSa3JbMVOhJqNO8cprgQGrD/b4YG4m964DmYqvRQGiG1GPR1qkn9eruD61M
EoeDVAXt0HDNWHSNbGlxs81Cgq16FvqMAtX51zU2o34yWlg03h9AU7M7dUEfCA9I
OR5aQREe+R1Cf7YMrcPgrAvhfjjzgteV+od3b02VvBakbbThy/b5bglDfPxVBchu
4uTcVltfKmB7aHemYdFv/JHtsrQwRkLfnTLmjnAR78dC34nng9U2Jw4QPHKg38J2
C1Rm5nSh7WfR+BuGh6CpYQm+WbP9KvxFoGJwxBdN5wIDAQABo1MwUTAdBgNVHQ4E
FgQUtwLorEAanqwkqb8NH/uzgOS8woUwHwYDVR0jBBgwFoAUtwLorEAanqwkqb8N
H/uzgOS8woUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWbot
LljC5OmHFbeIrXkwax481pectxdg9nC70rJgkgO62M+AaZLTq6UytiIy7LMNOAIx
1gCtc/IKHo8kp3DDXO+I9UQCG/yS4yqX+1Q2haOchS4Ug0zeSoi5LAEdWrBpPzOa
sOspjgQ8AP5TOiDumSDzK/9Uku8+NJMjHyC6Vwqrn85vLCQPq8W3pGzGW5mKazOB
2tclej9TZZN5+5wo7ZH6USNnbfP8KUVqPEbCDjeTpMeTWVxOF5Tqvf7wRqr7LqVu
Lpw5wrpPbfqKud2IjF5bN6n+/gNFBanr9SsaZGLVsmLvI51dD3BamyglgfRvs14Q
Ki3PSQGU5VFC47kLSA==
-----END CERTIFICATE-----`;

  beforeAll(async () => {
    adapter = new RealPostgresAuthAdapter();
    service = new AuthService(adapter);
    router = new AuthRestV1Router(service);

    await (adapter as any).pool.query(
      `DELETE FROM auth_oauth_clients WHERE id LIKE 'client_e2e_%' OR id LIKE 'client_holder_%' OR id LIKE 'client_sender_%'`
    );
  });

  it('issues certificate-bound token when authenticating via self_signed_tls_client_auth', async () => {
    const thumbprint = mtlsValidator.calculateThumbprintFromDerOrPem(CERT_A);
    const orgRes = await (adapter as any).pool.query(`SELECT id FROM auth_organizations LIMIT 1`);
    const orgId = orgRes.rows[0].id;
    const clientId = `client_e2e_mtls_${Date.now()}`;

    const clientRecord: OAuthClientRecord = {
      id: clientId,
      org_id: orgId,
      client_name: 'E2E Microservice',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: [],
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      token_endpoint_auth_method: 'self_signed_tls_client_auth',
      certificate_thumbprint: thumbprint,
    };

    await adapter.saveOAuthClient(clientRecord);

    const tokenRes = await router.route(
      'POST',
      '/oauth/token',
      {
        grant_type: 'client_credentials',
        client_id: clientId,
      },
      {
        'x-client-cert': CERT_A,
      }
    );

    expect(tokenRes.statusCode).toBe(200);
    const payload = tokenRes.payload.data as any;
    expect(payload.access_token).toBeDefined();

    const decoded = await service.verifySignedJwt(payload.access_token);
    expect(decoded.payload.cnf).toBeDefined();
    expect(decoded.payload.cnf['x5t#S256']).toBe(thumbprint);
  });

  it('rejects access to protected endpoint when certificate-bound token is presented without client certificate', async () => {
    const thumbprint = mtlsValidator.calculateThumbprintFromDerOrPem(CERT_B);
    const orgRes = await (adapter as any).pool.query(`SELECT id FROM auth_organizations LIMIT 1`);
    const orgId = orgRes.rows[0].id;
    const clientId = `client_holder_${Date.now()}`;

    const clientRecord: OAuthClientRecord = {
      id: clientId,
      org_id: orgId,
      client_name: 'Holder Workload',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: [],
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      token_endpoint_auth_method: 'self_signed_tls_client_auth',
      certificate_thumbprint: thumbprint,
    };

    await adapter.saveOAuthClient(clientRecord);

    const tokenRes = await router.route(
      'POST',
      '/oauth/token',
      { grant_type: 'client_credentials', client_id: clientId },
      { 'x-client-cert': CERT_B }
    );

    const accessToken = (tokenRes.payload.data as any).access_token;

    const accessWithoutCert = await router.route(
      'GET',
      '/api/v1/auth/organizations',
      undefined,
      { authorization: `Bearer ${accessToken}` }
    );

    expect(accessWithoutCert.statusCode).toBe(401);
    expect(accessWithoutCert.payload.message).toContain('Certificate-bound access token requires presented client certificate');
  });

  it('rejects access when token sender presents a different certificate than the bound thumbprint', async () => {
    const thumbprint = mtlsValidator.calculateThumbprintFromDerOrPem(CERT_C);
    const orgRes = await (adapter as any).pool.query(`SELECT id FROM auth_organizations LIMIT 1`);
    const orgId = orgRes.rows[0].id;
    const clientId = `client_sender_${Date.now()}`;

    const clientRecord: OAuthClientRecord = {
      id: clientId,
      org_id: orgId,
      client_name: 'Sender Workload',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: [],
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      token_endpoint_auth_method: 'self_signed_tls_client_auth',
      certificate_thumbprint: thumbprint,
    };

    await adapter.saveOAuthClient(clientRecord);

    const tokenRes = await router.route(
      'POST',
      '/oauth/token',
      { grant_type: 'client_credentials', client_id: clientId },
      { 'x-client-cert': CERT_C }
    );

    const accessToken = (tokenRes.payload.data as any).access_token;

    const hijackedAccess = await router.route(
      'GET',
      '/api/v1/auth/organizations',
      undefined,
      {
        authorization: `Bearer ${accessToken}`,
        'x-client-cert': CERT_B,
      }
    );

    expect(hijackedAccess.statusCode).toBe(401);
    expect(hijackedAccess.payload.message).toContain('Client certificate thumbprint mismatch with token certificate binding');
  });
});

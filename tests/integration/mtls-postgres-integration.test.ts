import { describe, it, expect, beforeAll } from 'vitest';
import { Pool } from 'pg';
import { RealPostgresAuthAdapter } from '../../src/infra/adapters/postgres/real-postgres-auth.adapter';
import { MtlsValidatorService } from '../../src/features/auth/services/mtls-validator.service';
import type { OAuthClientRecord } from '../../src/features/auth/ports/oidc-repository.port';

describe('mTLS PostgreSQL Integration & Constraint Safety (RFC 8705)', () => {
  let pool: Pool;
  let adapter: RealPostgresAuthAdapter;
  const mtlsService = new MtlsValidatorService();

  const CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUNMfqPSI9vO3yclLyTXolwhCepq4wDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVd29ya2xvYWQuaW50ZXJuYWwubmV0MB4XDTI2MTAxNjA2
MzQxOFoXDTI2MTExNTA2MzQxOFowIDEeMBwGA1UEAwwVd29ya2xvYWQuaW50ZXJu
YWwubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2pF4KVl/qZE3
Ytcljk9GIKe6dCTvIMNCfL6jA3UCx92ftWyhoZe0MlJMeYdyySRNn3ohONwexnF3
2NWgSOxeObHkgUbrDwl9dSKoH89AcBkIdOXqoMDfHZb4+PYzz7hmEu0FLYC0T0EH
hzi5/RVYSTY68Dlyb4XjL/H7fJPbV6xEtVMmDGsj0XQe3AbFtRvs2cYRLnvUQyKs
ysC2Pb+K3DRstslJXm3gnjqeY/wQRWJj158Est4whxWULF54Qtm12tpsP+UTVOSS
UMlvzj2I11uWRm5FAJhyM/8C7lmuMT8CWcQholCKcz02RwAEwrKvmruvKyPKvqf3
WT8aqaPSOQIDAQABo1MwUTAdBgNVHQ4EFgQUmFl+be5jjnfHdynCgD79od5WFNww
HwYDVR0jBBgwFoAUmFl+be5jjnfHdynCgD79od5WFNwwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAsJ7K6S01CIyZGiV41nG3cjkHqg0CAcrYIEy8
kUi+4A6uidP35YRNMgg0wvXS+ogsYivAwOkPFBj+uMB5hQui0I0m/jearBuYW8BL
UHvo1l7426n6JeLyePHUb+oAmIVhjFnpQjSXWHPA7aERlryQA125YqClFwnRYiVk
35AKzgFYOgyzjmgeeJvWwuiU9ebEBUVp2vc4Ud02Rm7RlIyGX5Z8E7O23Wy6Crua
ORJkTwfRtw562T48XCLxfBmCJQ16sIw0pIlTASxQD+Kc2B/hkb+f2if37eKeZjNE
D81iJH1KX65aQXdMzOA1qUOEdr9rTf/9c8W0tapVSdRQSBA/Kw==
-----END CERTIFICATE-----`;

  beforeAll(async () => {
    const connStr = process.env.DATABASE_URL || 'postgresql://admin:llmobs_s3cret_2026@localhost:5432/llm_observability';
    pool = new Pool({ connectionString: connStr });
    adapter = new RealPostgresAuthAdapter(connStr);

    await pool.query(
      `DELETE FROM auth_oauth_clients WHERE id LIKE 'client_mtls_%' OR id LIKE 'client_a_%' OR id LIKE 'client_b_%'`
    );
  });

  it('persists and retrieves mTLS oauth client configuration cleanly', async () => {
    const thumbprint = mtlsService.calculateThumbprintFromDerOrPem(CERT_PEM);
    const orgRes = await pool.query(`SELECT id FROM auth_organizations LIMIT 1`);
    const orgId = orgRes.rows[0].id;
    const clientId = `client_mtls_${Date.now()}`;

    const clientRecord: OAuthClientRecord = {
      id: clientId,
      org_id: orgId,
      client_name: 'Microservice Workload',
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

    const fetched = await adapter.findOAuthClientById(clientId);
    expect(fetched).not.toBeNull();
    expect(fetched?.token_endpoint_auth_method).toBe('self_signed_tls_client_auth');
    expect(fetched?.certificate_thumbprint).toBe(thumbprint);
  });

  it('database constraint enforces client_type = confidential for mTLS clients', async () => {
    const orgRes = await pool.query(`SELECT id FROM auth_organizations LIMIT 1`);
    const orgId = orgRes.rows[0].id;
    const clientId = `client_viol_${Date.now()}`;

    await expect(
      pool.query(
        `INSERT INTO auth_oauth_clients (id, org_id, client_name, client_type, token_endpoint_auth_method, certificate_thumbprint, created_at_ms)
         VALUES ($1, $2, $3, 'public', 'self_signed_tls_client_auth', 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde', $4)`,
        [clientId, orgId, 'Invalid Public mTLS Client', Date.now()]
      )
    ).rejects.toThrow(/auth_oauth_clients_mtls_confidential_ck/);
  });

  it('database unique constraint blocks duplicate certificate thumbprints across tenants', async () => {
    const orgRes = await pool.query(`SELECT id FROM auth_organizations LIMIT 1`);
    const orgId = orgRes.rows[0].id;
    const thumbprint = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-99999';

    await pool.query(
      `INSERT INTO auth_oauth_clients (id, org_id, client_name, client_type, token_endpoint_auth_method, certificate_thumbprint, created_at_ms)
       VALUES ($1, $2, $3, 'confidential', 'self_signed_tls_client_auth', $4, $5)`,
      [`client_a_${Date.now()}`, orgId, 'Tenant A Workload', thumbprint, Date.now()]
    );

    await expect(
      pool.query(
        `INSERT INTO auth_oauth_clients (id, org_id, client_name, client_type, token_endpoint_auth_method, certificate_thumbprint, created_at_ms)
         VALUES ($1, $2, $3, 'confidential', 'self_signed_tls_client_auth', $4, $5)`,
        [`client_b_${Date.now()}`, orgId, 'Tenant B Hijacker Workload', thumbprint, Date.now()]
      )
    ).rejects.toThrow(/uq_auth_oauth_clients_cert_thumbprint/);
  });
});

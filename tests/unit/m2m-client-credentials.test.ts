import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'crypto';
import { OidcProviderService } from '../../src/features/auth/services/oidc-provider.service';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { UnauthorizedError, ValidationError } from '../../src/shared/errors/auth.errors';

describe('M2M Client Credentials Grant (RFC 6749 §4.4, ADR 0034)', () => {
  let repo: AlloyDBOmniAuthAdapter;
  let oidcService: OidcProviderService;
  const orgId = 'org_m2m_test';
  const clientId = 'm2m_client_worker';
  const rawSecret = 'sec_live_999888777666555444333222111000';
  const secretHash = createHash('sha256').update(rawSecret).digest('hex');

  beforeEach(async () => {
    repo = new AlloyDBOmniAuthAdapter();
    oidcService = new OidcProviderService(repo, {
      issuer: 'http://localhost:3001',
      codeTtlMs: 300000,
      tokenTtlSeconds: 3600,
    });

    await repo.saveOAuthClient({
      id: clientId,
      org_id: orgId,
      client_name: 'Background Worker Daemon',
      client_secret_hash: secretHash,
      secret_prefix: rawSecret.substring(0, 12),
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: ['token'],
      allowed_scopes: ['metrics:write', 'traces:read', 'telemetry:ingest'],
      token_ttl_seconds: 1800,
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
    });
  });

  it('issues an asymmetric RS256 token when valid credentials are provided', async () => {
    const tokenResponse = await oidcService.issueClientCredentialsToken({
      client_id: clientId,
      client_secret: rawSecret,
      scope: 'metrics:write traces:read',
    });

    expect(tokenResponse).toBeDefined();
    expect(tokenResponse.token_type).toBe('Bearer');
    expect(tokenResponse.expires_in).toBe(1800);
    expect(tokenResponse.scope).toBe('metrics:write traces:read');
    expect(typeof tokenResponse.access_token).toBe('string');

    const parts = tokenResponse.access_token.split('.');
    expect(parts.length).toBe(3);

    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    expect(payload.sub).toBe(clientId);
    expect(payload.client_id).toBe(clientId);
    expect(payload.org_id).toBe(orgId);
    expect(payload.scope).toBe('metrics:write traces:read');
    expect(payload.token_use).toBe('access_token');
    expect(payload.iss).toBe('http://localhost:3001');
  });

  it('rejects authentication with invalid client secret', async () => {
    await expect(
      oidcService.issueClientCredentialsToken({
        client_id: clientId,
        client_secret: 'invalid_secret_value',
      })
    ).rejects.toThrow(UnauthorizedError);
  });

  it('rejects when client is not authorized for client_credentials grant', async () => {
    const pubClientId = 'public_app_client';
    await repo.saveOAuthClient({
      id: pubClientId,
      org_id: orgId,
      client_name: 'Public Web App',
      redirect_uris: ['http://localhost:3000/callback'],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      client_type: 'public',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
    });

    await expect(
      oidcService.issueClientCredentialsToken({
        client_id: pubClientId,
        client_secret: rawSecret,
      })
    ).rejects.toThrow(UnauthorizedError);
  });

  it('rejects request with unauthorized scope', async () => {
    await expect(
      oidcService.issueClientCredentialsToken({
        client_id: clientId,
        client_secret: rawSecret,
        scope: 'admin:super_write',
      })
    ).rejects.toThrow(ValidationError);
  });
});

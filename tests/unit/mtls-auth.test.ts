import { describe, it, expect } from 'vitest';
import { MtlsValidatorService } from '../../src/features/auth/services/mtls-validator.service';
import type { OAuthClientRecord } from '../../src/features/auth/ports/oidc-repository.port';
import { UnauthorizedError } from '../../src/shared/errors/auth.errors';

describe('MtlsValidatorService (RFC 8705)', () => {
  const service = new MtlsValidatorService();

  const CERT_1_PEM = `-----BEGIN CERTIFICATE-----
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

  const CERT_2_PEM = `-----BEGIN CERTIFICATE-----
MIIDbzCCAlegAwIBAgIUekdYCo0pjVcZVz4/H8dyZHZ8JrAwDQYJKoZIhvcNAQEL
BQAwRzEfMB0GA1UEAwwWc2VydmljZS1hLnByb2QuY2x1c3RlcjEUMBIGA1UECgwL
RW5naW5lZXJpbmcxDjAMBgNVBAsMBUNsb3VkMB4XDTI2MTAxNjA2MzQxOVoXDTI2
MTExNTA2MzQxOVowRzEfMB0GA1UEAwwWc2VydmljZS1hLnByb2QuY2x1c3RlcjEU
MBIGA1UECgwLRW5naW5lZXJpbmcxDjAMBgNVBAsMBUNsb3VkMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqHzo0XQzdoxxDhAH+S4+GzzVwrWugpGGE6Kx
teivBS+JBoICfHa3E/fCessz9S+I82Up7FF3C3rEA32Fv7m/vWpx6sgQ/SJBq42w
7udTNaNF12W6NclA3FOxHuuwN70kqng+0BmoQSn8gk4LGGYnTimHX5/iCQkF5OyC
wsqxfgLfoF9/NM0n5jenCuo4cHuwMjIjKVkb9CygpmTCA01jOCtBN04iqxpY4wE9
POpyuG1VN6TpOHLVNNWISmgkGg4ct92XL5Oowj3nUnma9/XXbB7xr5jK67ECDElp
2xuI6fa0fE4IroW4qMj3ZHsUGZhwHy/sxOnTg3gi83SwmAltTwIDAQABo1MwUTAd
BgNVHQ4EFgQU+R6pI6OBkxwGAcv+PGykNZmEX08wHwYDVR0jBBgwFoAU+R6pI6OB
kxwGAcv+PGykNZmEX08wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEARNMmEQczbWQIAhclNER3GJzpZn0czLBO8awqyCDQf6CSL15G3O4j/XBpT/m/
Qv0aA0wn2cGLKz+C7xrOoURGBUjlcvo+hXQSz6H4xtdwvnRrTlCIfHi6rAgRZNLJ
GaqC4Vg6fchd89iV74KWW0zdYw2dsRNjDXjQ5IRgS8soVeNtFVi4J8M+rsRoKcpB
bISg3lrs4/JTU1s3iVQF/GKWxcWtZ9yUE01PXEU+spDaPoTis2WFVT1su2mR0nrI
SYwPDbMEMXn6L1Y2e2anAQhOBub0sH/WJK7igPh0zwOU9k+amY6InhWDC7ixVSJC
063LwjgYOrfL0WxZ+4N+IOoSbw==
-----END CERTIFICATE-----`;

  it('correctly calculates SHA-256 base64url thumbprint from X.509 PEM', () => {
    const thumbprint = service.calculateThumbprintFromDerOrPem(CERT_1_PEM);

    expect(thumbprint).toBeDefined();
    expect(thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('authenticates client with self_signed_tls_client_auth matching pinned thumbprint', () => {
    const thumbprint = service.calculateThumbprintFromDerOrPem(CERT_1_PEM);

    const client: OAuthClientRecord = {
      id: 'client_mtls_1',
      org_id: 'org_test',
      client_name: 'Workload 1',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: [],
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      token_endpoint_auth_method: 'self_signed_tls_client_auth',
      certificate_thumbprint: thumbprint,
    };

    const result = service.verifyClientMtlsAuthentication(client, CERT_1_PEM);
    expect(result.thumbprintSha256).toBe(thumbprint);
  });

  it('rejects self_signed_tls_client_auth when presented certificate thumbprint does not match pinned thumbprint', () => {
    const registeredThumbprint = service.calculateThumbprintFromDerOrPem(CERT_1_PEM);

    const client: OAuthClientRecord = {
      id: 'client_mtls_1',
      org_id: 'org_test',
      client_name: 'Workload 1',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: [],
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      token_endpoint_auth_method: 'self_signed_tls_client_auth',
      certificate_thumbprint: registeredThumbprint,
    };

    expect(() => service.verifyClientMtlsAuthentication(client, CERT_2_PEM)).toThrow(UnauthorizedError);
  });

  it('authenticates client with tls_client_auth matching canonical Subject DN', () => {
    const parsed = service.parseCertificate(CERT_2_PEM);

    const client: OAuthClientRecord = {
      id: 'client_mtls_2',
      org_id: 'org_test',
      client_name: 'Service A',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: [],
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      token_endpoint_auth_method: 'tls_client_auth',
      tls_client_auth_subject_dn: parsed.subjectDn,
    };

    const result = service.verifyClientMtlsAuthentication(client, CERT_2_PEM);
    expect(result.thumbprintSha256).toBe(parsed.thumbprintSha256);
  });

  it('rejects tls_client_auth when Subject DN does not match', () => {
    const client: OAuthClientRecord = {
      id: 'client_mtls_2',
      org_id: 'org_test',
      client_name: 'Service A',
      redirect_uris: [],
      grant_types: ['client_credentials'],
      response_types: [],
      client_type: 'confidential',
      status: 'ACTIVE',
      created_at_ms: Date.now(),
      token_endpoint_auth_method: 'tls_client_auth',
      tls_client_auth_subject_dn: 'CN=unmatched.service.net',
    };

    expect(() => service.verifyClientMtlsAuthentication(client, CERT_2_PEM)).toThrow(UnauthorizedError);
  });

  it('verifies certificate binding matches token cnf thumbprint and rejects mismatched certificates', () => {
    const validThumbprint = service.calculateThumbprintFromDerOrPem(CERT_1_PEM);

    expect(service.verifyCertificateBinding(validThumbprint, CERT_1_PEM)).toBe(true);
    expect(service.verifyCertificateBinding(validThumbprint, CERT_2_PEM)).toBe(false);
    expect(service.verifyCertificateBinding(validThumbprint, undefined)).toBe(false);
  });

  it('parses URL-encoded certificate strings accurately', () => {
    const urlEncoded = encodeURIComponent(CERT_1_PEM);
    const parsed = service.parseCertificate(urlEncoded);
    const normalParsed = service.parseCertificate(CERT_1_PEM);

    expect(parsed.thumbprintSha256).toBe(normalParsed.thumbprintSha256);
    expect(parsed.subjectDn).toBe(normalParsed.subjectDn);
  });
});

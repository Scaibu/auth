import { createHash, X509Certificate } from 'crypto';
import { UnauthorizedError } from '../../../shared/errors/auth.errors';
import type { OAuthClientRecord } from '../ports/oidc-repository.port';

export interface ClientCertificateExtraction {
  readonly clientCertRaw?: string;
  readonly clientCertSha256?: string;
  readonly clientCertSubjectDn?: string;
}

export interface ParsedClientCertificate {
  readonly thumbprintSha256: string;
  readonly subjectDn: string;
  readonly validFromMs: number;
  readonly validToMs: number;
}

export class MtlsValidatorService {
  parseCertificate(certPemOrUrlEncoded: string): ParsedClientCertificate {
    if (!certPemOrUrlEncoded || typeof certPemOrUrlEncoded !== 'string') {
      throw new UnauthorizedError('Missing or empty client certificate payload');
    }

    let decoded = certPemOrUrlEncoded.trim();
    if (decoded.includes('%')) {
      try {
        decoded = decodeURIComponent(decoded);
      } catch {
        throw new UnauthorizedError('Malformed URL-encoded client certificate payload');
      }
    }

    if (!decoded.includes('-----BEGIN CERTIFICATE-----')) {
      const cleaned = decoded.replace(/\s+/g, '');
      decoded = `-----BEGIN CERTIFICATE-----\n${cleaned}\n-----END CERTIFICATE-----`;
    }

    try {
      const x509 = new X509Certificate(decoded);
      const nowMs = Date.now();
      const validFromMs = Date.parse(x509.validFrom);
      const validToMs = Date.parse(x509.validTo);

      if (nowMs < validFromMs) {
        throw new UnauthorizedError('Client certificate is not yet valid');
      }

      if (nowMs > validToMs) {
        throw new UnauthorizedError('Client certificate has expired');
      }

      const thumbprintSha256 = createHash('sha256')
        .update(x509.raw)
        .digest('base64url');

      return {
        thumbprintSha256,
        subjectDn: x509.subject,
        validFromMs,
        validToMs,
      };
    } catch (err: unknown) {
      if (err instanceof UnauthorizedError) {
        throw err;
      }
      throw new UnauthorizedError('Invalid X.509 client certificate structure');
    }
  }

  calculateThumbprintFromDerOrPem(payload: string): string {
    const parsed = this.parseCertificate(payload);
    return parsed.thumbprintSha256;
  }

  verifyClientMtlsAuthentication(
    client: OAuthClientRecord,
    certPayload?: string
  ): { readonly thumbprintSha256: string } {
    const authMethod = client.token_endpoint_auth_method ?? 'client_secret_post';

    if (authMethod !== 'tls_client_auth' && authMethod !== 'self_signed_tls_client_auth') {
      throw new UnauthorizedError(`OAuth client is not configured for mTLS client authentication (configured: ${authMethod})`);
    }

    if (!certPayload || typeof certPayload !== 'string' || certPayload.trim().length === 0) {
      throw new UnauthorizedError('Client certificate is required for mTLS authentication');
    }

    const cert = this.parseCertificate(certPayload);

    if (authMethod === 'self_signed_tls_client_auth') {
      if (!client.certificate_thumbprint) {
        throw new UnauthorizedError('OAuth client missing registered certificate thumbprint');
      }

      if (cert.thumbprintSha256 !== client.certificate_thumbprint) {
        throw new UnauthorizedError('Client certificate thumbprint mismatch with registered pinned thumbprint');
      }

      return { thumbprintSha256: cert.thumbprintSha256 };
    }

    if (!client.tls_client_auth_subject_dn) {
      throw new UnauthorizedError('OAuth client missing registered subject DN');
    }

    const normalizedRegisteredDn = this.canonicalizeDn(client.tls_client_auth_subject_dn);
    const normalizedCertDn = this.canonicalizeDn(cert.subjectDn);

    if (normalizedRegisteredDn !== normalizedCertDn) {
      throw new UnauthorizedError('Client certificate Subject DN mismatch with registered PKI DN');
    }

    return { thumbprintSha256: cert.thumbprintSha256 };
  }

  verifyCertificateBinding(
    tokenCnfThumbprint: string,
    presentedCertPayload?: string
  ): boolean {
    if (!tokenCnfThumbprint || typeof tokenCnfThumbprint !== 'string') {
      return false;
    }

    if (!presentedCertPayload || typeof presentedCertPayload !== 'string') {
      return false;
    }

    try {
      const cert = this.parseCertificate(presentedCertPayload);
      return cert.thumbprintSha256 === tokenCnfThumbprint;
    } catch {
      return false;
    }
  }

  private canonicalizeDn(dn: string): string {
    return dn
      .split(/[,\n]/)
      .map((part) => part.trim())
      .filter((part) => part.length > 0)
      .map((part) => {
        const eqIdx = part.indexOf('=');
        if (eqIdx === -1) {
          return part.toLowerCase();
        }
        const key = part.slice(0, eqIdx).trim().toUpperCase();
        const value = part.slice(eqIdx + 1).trim();
        return `${key}=${value}`;
      })
      .sort()
      .join(',');
  }
}

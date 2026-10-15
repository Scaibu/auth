export interface OidcConfig {
  readonly issuer: string;
  readonly codeTtlMs: number;
  readonly tokenTtlSeconds: number;
}

export const DEFAULT_OIDC_CONFIG = Object.freeze({
  issuer: 'https://auth.observability.io',
  codeTtlMs: 300000,
  tokenTtlSeconds: 3600,
});

export function loadOidcConfig(): OidcConfig {
  return Object.freeze({
    issuer: process.env.AUTH_OIDC_ISSUER || DEFAULT_OIDC_CONFIG.issuer,
    codeTtlMs: parseInt(
      process.env.AUTH_OIDC_CODE_TTL_MS || String(DEFAULT_OIDC_CONFIG.codeTtlMs),
      10,
    ),
    tokenTtlSeconds: parseInt(
      process.env.AUTH_OIDC_TOKEN_TTL_SECONDS || String(DEFAULT_OIDC_CONFIG.tokenTtlSeconds),
      10,
    ),
  });
}


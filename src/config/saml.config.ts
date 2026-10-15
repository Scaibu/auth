export interface SamlConfig {
  readonly spEntityId: string;
  readonly acsUrl: string;
  readonly clockSkewMs: number;
  readonly relayStateTtlMs: number;
}

export const DEFAULT_SAML_CONFIG: SamlConfig = Object.freeze({
  spEntityId: 'https://auth.observability.io/api/v1/auth/saml/metadata',
  acsUrl: 'https://auth.observability.io/api/v1/auth/saml/acs',
  clockSkewMs: 120000,
  relayStateTtlMs: 300000,
});

export function loadSamlConfig(): SamlConfig {
  return Object.freeze({
    spEntityId: process.env.AUTH_SAML_SP_ENTITY_ID || DEFAULT_SAML_CONFIG.spEntityId,
    acsUrl: process.env.AUTH_SAML_ACS_URL || DEFAULT_SAML_CONFIG.acsUrl,
    clockSkewMs: parseInt(
      process.env.AUTH_SAML_CLOCK_SKEW_MS || String(DEFAULT_SAML_CONFIG.clockSkewMs),
      10,
    ),
    relayStateTtlMs: parseInt(
      process.env.AUTH_SAML_RELAY_STATE_TTL_MS || String(DEFAULT_SAML_CONFIG.relayStateTtlMs),
      10,
    ),
  });
}

export interface SamlProviderRecord {
  readonly id: string;
  readonly org_id: string;
  readonly idp_entity_id: string;
  readonly idp_sso_url: string;
  readonly idp_certificate_pem: string;
  readonly sp_entity_id: string;
  readonly attribute_mapping: Readonly<Record<string, string>>;
  readonly status: 'ACTIVE' | 'SUSPENDED';
  readonly created_at_ms: number;
  readonly deleted_at?: Date | null;
}

export interface SamlRequestRecord {
  readonly relay_state: string;
  readonly org_id: string;
  readonly provider_id: string;
  readonly request_id: string;
  readonly return_url?: string;
  readonly expires_at_ms: number;
  readonly created_at_ms: number;
}

export interface RegisterSamlProviderInput {
  readonly idp_entity_id: string;
  readonly idp_sso_url: string;
  readonly idp_certificate_pem: string;
  readonly sp_entity_id?: string;
  readonly attribute_mapping?: Record<string, string>;
}

export interface SamlLoginResult {
  readonly redirect_url: string;
  readonly relay_state: string;
}

export interface SamlAuthResult {
  readonly token: string;
  readonly user: {
    readonly id: string;
    readonly email: string;
    readonly name: string;
    readonly org_id: string;
    readonly role: string;
  };
}

export interface SamlRepositoryPort {
  saveSamlProvider(provider: SamlProviderRecord): Promise<void>;
  findSamlProviderByOrgId(orgId: string): Promise<SamlProviderRecord | null>;
  findSamlProviderById(id: string): Promise<SamlProviderRecord | null>;
  listSamlProviders(orgId: string): Promise<ReadonlyArray<SamlProviderRecord>>;
  saveSamlRequest(request: SamlRequestRecord): Promise<void>;
  consumeSamlRequest(relayState: string): Promise<SamlRequestRecord | null>;
  recordAssertionId(assertionId: string, expiresAtMs: number): Promise<boolean>;
}

export interface OAuthClientRecord {
  readonly id: string;
  readonly org_id: string;
  readonly client_name: string;
  readonly client_secret_hash?: string;
  readonly redirect_uris: ReadonlyArray<string>;
  readonly grant_types: ReadonlyArray<string>;
  readonly response_types: ReadonlyArray<string>;
  readonly client_type: 'public' | 'confidential';
  readonly status: 'ACTIVE' | 'SUSPENDED';
  readonly created_at_ms: number;
}

export interface OAuthAuthorizationCodeRecord {
  readonly code: string;
  readonly client_id: string;
  readonly user_id: string;
  readonly org_id: string;
  readonly redirect_uri: string;
  readonly code_challenge: string;
  readonly code_challenge_method: 'S256';
  readonly scope: string;
  readonly used: boolean;
  readonly expires_at_ms: number;
  readonly created_at_ms: number;
}

export interface SigningKeyRecord {
  readonly kid: string;
  readonly kty: string;
  readonly alg: string;
  readonly use: string;
  readonly public_key_pem: string;
  readonly private_key_pem: string;
  readonly status: 'ACTIVE' | 'RETIRED';
  readonly created_at_ms: number;
}

export interface JwksKey {
  readonly kty: string;
  readonly use: string;
  readonly kid: string;
  readonly alg: string;
  readonly n: string;
  readonly e: string;
}

export interface OidcTokenResponse {
  readonly access_token: string;
  readonly token_type: 'Bearer';
  readonly expires_in: number;
  readonly id_token: string;
  readonly scope: string;
}

export interface OidcUserInfoResponse {
  readonly sub: string;
  readonly email: string;
  readonly name: string;
  readonly email_verified: boolean;
  readonly org_id: string;
}

export interface OidcRepositoryPort {
  saveOAuthClient(client: OAuthClientRecord): Promise<void>;
  findOAuthClientById(clientId: string): Promise<OAuthClientRecord | null>;
  
  saveAuthorizationCode(codeRecord: OAuthAuthorizationCodeRecord): Promise<void>;
  findAuthorizationCode(code: string): Promise<OAuthAuthorizationCodeRecord | null>;
  consumeAuthorizationCode(code: string): Promise<void>;
  
  saveSigningKey(key: SigningKeyRecord): Promise<void>;
  getActiveSigningKey(): Promise<SigningKeyRecord | null>;
  listPublicJwksKeys(): Promise<ReadonlyArray<JwksKey>>;
}

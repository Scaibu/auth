export interface MfaSetupResult {
  secret: string;
  otpauthUrl: string;
  qrCodeDataUrl?: string;
}

export interface MfaVerificationResult {
  mfaEnabled: boolean;
  recoveryCodes: string[];
}

export interface MfaChallengeResult {
  token: string;
  user: {
    id: string;
    email: string;
    organization_id: string;
    role: string;
  };
  usedRecoveryCode?: boolean;
}

export interface MfaRecoveryCodeRecord {
  id: string;
  user_id: string;
  code_hash: string;
  used: boolean;
  created_at_ms: number;
  used_at_ms?: number;
}

export interface MfaPort {
  generateSecret(): string;
  generateTotpUri(email: string, secret: string, issuer?: string): string;
  verifyTotpCode(secret: string, token: string, window?: number): boolean;
  generateRecoveryCodes(count?: number): string[];
  hashRecoveryCode(code: string): string;
}

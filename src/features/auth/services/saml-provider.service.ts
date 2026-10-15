import { createVerify } from 'crypto';
import type { AuthRepositoryPort } from '../repository';
import type {
  SamlProviderRecord,
  RegisterSamlProviderInput,
  SamlLoginResult,
  SamlAuthResult,
} from '../ports/saml-repository.port';
import type { SamlConfig } from '../../../config/saml.config';
import { loadSamlConfig } from '../../../config/saml.config';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { ValidationError, NotFoundError, UnauthorizedError } from '../../../shared/errors/auth.errors';
import { withSpan } from '../../../infra/tracing/tracer';
import { buildSpMetadataXml, buildAuthNRequestXml } from '../../../shared/utils/saml-xml.builder';

export class SamlProviderService {
  private readonly config: SamlConfig;

  constructor(
    private readonly repo: AuthRepositoryPort,
    config?: SamlConfig,
  ) {
    this.config = config ?? loadSamlConfig();
  }

  async getSpMetadata(): Promise<string> {
    return buildSpMetadataXml({
      spEntityId: this.config.spEntityId,
      acsUrl: this.config.acsUrl,
    });
  }

  async registerProvider(orgId: string, input: RegisterSamlProviderInput): Promise<SamlProviderRecord> {
    return withSpan('SamlProviderService.registerProvider', async () => {
      const now = Date.now();
      const id = `saml_prov_${now}_${Math.random().toString(36).substring(2, 10)}`;

      const record: SamlProviderRecord = {
        id,
        org_id: orgId,
        idp_entity_id: input.idp_entity_id.trim(),
        idp_sso_url: input.idp_sso_url.trim(),
        idp_certificate_pem: input.idp_certificate_pem.trim(),
        sp_entity_id: input.sp_entity_id?.trim() || this.config.spEntityId,
        attribute_mapping: Object.freeze(input.attribute_mapping ?? { email: 'email', name: 'name' }),
        status: 'ACTIVE',
        created_at_ms: now,
      };

      await this.repo.saveSamlProvider(record);
      return record;
    });
  }

  async listProviders(orgId: string): Promise<ReadonlyArray<SamlProviderRecord>> {
    return this.repo.listSamlProviders(orgId);
  }

  async initiateLogin(orgId: string, returnUrl?: string): Promise<SamlLoginResult> {
    return withSpan('SamlProviderService.initiateLogin', async () => {
      const provider = await this.repo.findSamlProviderByOrgId(orgId);
      if (!provider || provider.status !== 'ACTIVE') {
        throw new NotFoundError(`No active SAML 2.0 Identity Provider configured for organization: ${orgId}`);
      }

      const now = Date.now();
      const requestId = `_req_${now}_${Math.random().toString(36).substring(2, 12)}`;
      const relayState = `relay_${now}_${Math.random().toString(36).substring(2, 14)}`;

      const authNRequestXml = buildAuthNRequestXml({
        requestId,
        issueInstantIso: new Date(now).toISOString(),
        destination: provider.idp_sso_url,
        acsUrl: this.config.acsUrl,
        issuer: provider.sp_entity_id,
      });

      const samlRequestBase64 = Buffer.from(authNRequestXml, 'utf-8').toString('base64');
      const encodedSamlRequest = encodeURIComponent(samlRequestBase64);
      const encodedRelayState = encodeURIComponent(relayState);

      const delimiter = provider.idp_sso_url.includes('?') ? '&' : '?';
      const redirectUrl = `${provider.idp_sso_url}${delimiter}SAMLRequest=${encodedSamlRequest}&RelayState=${encodedRelayState}`;

      await this.repo.saveSamlRequest({
        relay_state: relayState,
        org_id: orgId,
        provider_id: provider.id,
        request_id: requestId,
        return_url: returnUrl,
        expires_at_ms: now + this.config.relayStateTtlMs,
        created_at_ms: now,
      });

      return {
        redirect_url: redirectUrl,
        relay_state: relayState,
      };
    });
  }

  async consumeAssertion(samlResponseRaw: string, relayState: string): Promise<SamlAuthResult> {
    return withSpan('SamlProviderService.consumeAssertion', async () => {
      const samlRequest = await this.repo.consumeSamlRequest(relayState);
      if (!samlRequest || samlRequest.expires_at_ms < Date.now()) {
        throw new UnauthorizedError('SAML RelayState is invalid, expired, or previously consumed');
      }

      const provider = await this.repo.findSamlProviderById(samlRequest.provider_id);
      if (!provider || provider.status !== 'ACTIVE') {
        throw new UnauthorizedError('Configured SAML Identity Provider is inactive or not found');
      }

      const xml = this.decodeSamlResponse(samlResponseRaw);
      this.assertNoXxe(xml);

      const assertion = this.parseAssertion(xml);

      const isReplayAllowed = await this.repo.recordAssertionId(assertion.id, assertion.notOnOrAfterMs);
      if (!isReplayAllowed) {
        throw new UnauthorizedError(`SAML Assertion replay detected for ID: ${assertion.id}`);
      }

      const now = Date.now();
      const skew = this.config.clockSkewMs;
      if (assertion.notBeforeMs - skew > now || now > assertion.notOnOrAfterMs + skew) {
        throw new UnauthorizedError('SAML Assertion validity period expired or not yet valid');
      }

      if (assertion.audience !== provider.sp_entity_id && assertion.audience !== this.config.spEntityId) {
        throw new UnauthorizedError(`SAML Audience restriction mismatch: expected ${provider.sp_entity_id}, received ${assertion.audience}`);
      }

      const isSignatureValid = this.verifySignature(assertion.rawAssertionXml, provider.idp_certificate_pem, assertion.signatureValue);
      if (!isSignatureValid) {
        throw new UnauthorizedError('SAML XMLDSig cryptographic signature verification failed');
      }

      const email = assertion.attributes[provider.attribute_mapping.email || 'email'] || assertion.nameId;
      const rawName = assertion.attributes[provider.attribute_mapping.name || 'name'] || email.split('@')[0];
      const name = rawName && rawName.trim().length > 0 ? rawName : 'Enterprise User';

      let user = await this.repo.findUserByEmail(email);
      if (!user) {
        const userId = `usr_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
        await this.repo.createUser({
          id: userId,
          email,
          password_hash: '',
          name,
          org_id: samlRequest.org_id,
          org_name: 'Enterprise Organization',
          role: AUTH_CONSTANTS.ROLE_MEMBER,
          blocked: false,
          user_permissions: [AUTH_CONSTANTS.PERMISSION_TRACES_READ],
        });
        user = await this.repo.findUserById(userId);
      }

      if (!user) {
        throw new UnauthorizedError('Failed to locate or provision user record for SAML assertion');
      }

      const token = `saml_jwt_${Date.now()}_${Buffer.from(user.id).toString('base64url')}`;

      return {
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          org_id: user.org_id,
          role: user.role,
        },
      };
    });
  }

  private decodeSamlResponse(raw: string): string {
    const trimmed = raw.trim();
    if (trimmed.startsWith('<')) {
      return trimmed;
    }
    try {
      return Buffer.from(trimmed, 'base64').toString('utf-8');
    } catch {
      throw new ValidationError('Malformed SAMLResponse payload: base64 decoding failed');
    }
  }

  private assertNoXxe(xml: string): void {
    const lower = xml.toLowerCase();
    if (lower.includes('<!doctype') || lower.includes('<!entity') || lower.includes('system') || lower.includes('public')) {
      if (lower.includes('<!doctype') || lower.includes('<!entity')) {
        throw new ValidationError('XXE vulnerability detected: DOCTYPE and ENTITY declarations are forbidden');
      }
    }
  }

  private parseAssertion(xml: string): {
    id: string;
    nameId: string;
    audience: string;
    notBeforeMs: number;
    notOnOrAfterMs: number;
    signatureValue: string;
    attributes: Record<string, string>;
    rawAssertionXml: string;
  } {
    const assertionMatch = xml.match(/<(?:\w+:)?Assertion[\s\S]*?<\/(?:\w+:)?Assertion>/);
    const rawAssertionXml = assertionMatch ? assertionMatch[0] : xml;

    const idMatch = rawAssertionXml.match(/\bID="([^"]+)"/);
    const id = (idMatch && idMatch[1]) ? idMatch[1] : '';

    const nameIdMatch = rawAssertionXml.match(/<(?:\w+:)?NameID[^>]*>([^<]+)<\/(?:\w+:)?NameID>/);
    const nameId = (nameIdMatch && nameIdMatch[1]) ? nameIdMatch[1].trim() : '';

    const audienceMatch = rawAssertionXml.match(/<(?:\w+:)?Audience>([^<]+)<\/(?:\w+:)?Audience>/);
    const audience = (audienceMatch && audienceMatch[1]) ? audienceMatch[1].trim() : '';

    const conditionsMatch = rawAssertionXml.match(/<(?:\w+:)?Conditions[^>]*NotBefore="([^"]+)"[^>]*NotOnOrAfter="([^"]+)"/);
    const notBeforeStr = (conditionsMatch && conditionsMatch[1]) ? conditionsMatch[1] : new Date(Date.now() - 60000).toISOString();
    const notOnOrAfterStr = (conditionsMatch && conditionsMatch[2]) ? conditionsMatch[2] : new Date(Date.now() + 300000).toISOString();

    const notBeforeMs = new Date(notBeforeStr).getTime();
    const notOnOrAfterMs = new Date(notOnOrAfterStr).getTime();

    const sigMatch = rawAssertionXml.match(/<(?:\w+:)?SignatureValue[^>]*>([^<]+)<\/(?:\w+:)?SignatureValue>/);
    const signatureValue = (sigMatch && sigMatch[1]) ? sigMatch[1].replace(/\s+/g, '') : '';

    const attributes: Record<string, string> = {};
    const attrRegex = /<(?:\w+:)?Attribute[^>]*Name="([^"]+)"[^>]*>[\s\S]*?<(?:\w+:)?AttributeValue[^>]*>([^<]+)<\/(?:\w+:)?AttributeValue>[\s\S]*?<\/(?:\w+:)?Attribute>/g;
    let match: RegExpExecArray | null;
    while ((match = attrRegex.exec(rawAssertionXml)) !== null) {
      const attrKey = match[1];
      const attrVal = match[2];
      if (attrKey && attrVal) {
        attributes[attrKey] = attrVal.trim();
      }
    }

    if (!id || !nameId) {
      throw new ValidationError('Invalid SAML Assertion: Missing mandatory ID or NameID element');
    }

    return {
      id,
      nameId,
      audience,
      notBeforeMs,
      notOnOrAfterMs,
      signatureValue,
      attributes,
      rawAssertionXml,
    };
  }

  private verifySignature(assertionXml: string, certPem: string, signatureValue: string): boolean {
    if (!signatureValue) {
      return false;
    }
    try {
      const canonicalAssertion = assertionXml.replace(/<(?:\w+:)?Signature[\s\S]*?<\/(?:\w+:)?Signature>/, '');
      const verifier = createVerify('RSA-SHA256');
      verifier.update(canonicalAssertion);
      return verifier.verify(certPem, Buffer.from(signatureValue, 'base64'));
    } catch {
      return false;
    }
  }
}

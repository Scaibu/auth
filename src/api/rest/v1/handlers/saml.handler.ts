import type { AuthService } from '../../../../features/auth/service';
import { UnauthorizedError, ValidationError } from '../../../../shared/errors/auth.errors';

function extractRequiredString(val: unknown, fieldName: string): string {
  if (typeof val !== 'string') {
    throw new ValidationError(`Missing mandatory parameter: ${fieldName}`);
  }
  const trimmed = val.trim();
  if (trimmed.length === 0) {
    throw new ValidationError(`Parameter cannot be empty or blank: ${fieldName}`);
  }
  return trimmed;
}

export async function handleGetSamlMetadata(service: AuthService) {
  const xml = await service.getSamlSpMetadata();
  return {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
    data: xml,
  };
}

export async function handleInitiateSamlLogin(
  service: AuthService,
  queryParams?: Record<string, string>,
) {
  const orgId = extractRequiredString(queryParams?.org_id, 'org_id');
  const returnUrl = queryParams?.return_url?.trim();
  return service.initiateSamlLogin(orgId, returnUrl);
}

export async function handleConsumeSamlAssertion(service: AuthService, body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ValidationError('Request body must be a valid JSON object');
  }

  const payload = body as Record<string, unknown>;
  const samlResponse = extractRequiredString(payload.SAMLResponse || payload.saml_response, 'SAMLResponse');
  const relayState = extractRequiredString(payload.RelayState || payload.relay_state, 'RelayState');

  return service.consumeSamlAssertion(samlResponse, relayState);
}

export async function handleRegisterSamlProvider(
  service: AuthService,
  body: unknown,
  session?: { sub: string; role?: string; org?: { org_id: string; role?: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to register SAML provider');
  }
  const userRole = session?.role ?? session?.org?.role;
  if (userRole !== 'admin' && userRole !== 'SUPER_ADMIN') {
    throw new UnauthorizedError('Administrator privileges required to register SAML provider');
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ValidationError('Request body must be a valid JSON object');
  }

  const payload = body as Record<string, unknown>;
  const idpEntityId = extractRequiredString(payload.idp_entity_id, 'idp_entity_id');
  const idpSsoUrl = extractRequiredString(payload.idp_sso_url, 'idp_sso_url');
  const idpCert = extractRequiredString(payload.idp_certificate_pem, 'idp_certificate_pem');
  const spEntityId = typeof payload.sp_entity_id === 'string' ? payload.sp_entity_id.trim() : undefined;
  const attributeMapping = (payload.attribute_mapping && typeof payload.attribute_mapping === 'object' && !Array.isArray(payload.attribute_mapping))
    ? (payload.attribute_mapping as Record<string, string>)
    : undefined;

  return service.registerSamlProvider(session.org.org_id, {
    idp_entity_id: idpEntityId,
    idp_sso_url: idpSsoUrl,
    idp_certificate_pem: idpCert,
    sp_entity_id: spEntityId,
    attribute_mapping: attributeMapping,
  });
}

export async function handleListSamlProviders(
  service: AuthService,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to list SAML providers');
  }
  return service.listSamlProviders(session.org.org_id);
}

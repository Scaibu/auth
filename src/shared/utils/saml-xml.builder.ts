import { AUTH_CONSTANTS } from '../constants/auth.constants';

export interface SpMetadataXmlOptions {
  readonly spEntityId: string;
  readonly acsUrl: string;
  readonly nameIdFormat?: string;
  readonly binding?: string;
  readonly wantAssertionsSigned?: boolean;
  readonly authnRequestsSigned?: boolean;
}

export interface AuthNRequestXmlOptions {
  readonly requestId: string;
  readonly issueInstantIso: string;
  readonly destination: string;
  readonly acsUrl: string;
  readonly issuer: string;
  readonly binding?: string;
  readonly nameIdFormat?: string;
  readonly allowCreate?: boolean;
}

export function buildSpMetadataXml(options: SpMetadataXmlOptions): string {
  const binding = options.binding ?? AUTH_CONSTANTS.SAML.BINDING_HTTP_POST;
  const nameIdFormat = options.nameIdFormat ?? AUTH_CONSTANTS.SAML.NAMEID_FORMAT_EMAIL;
  const wantAssertionsSigned = options.wantAssertionsSigned ?? true;
  const authnRequestsSigned = options.authnRequestsSigned ?? false;

  return [
    AUTH_CONSTANTS.SAML.XML_PROLOG,
    `<md:EntityDescriptor xmlns:md="${AUTH_CONSTANTS.SAML.NS_METADATA}" entityID="${options.spEntityId}">`,
    `  <md:SPSSODescriptor protocolSupportEnumeration="${AUTH_CONSTANTS.SAML.NS_PROTOCOL}" AuthnRequestsSigned="${authnRequestsSigned}" WantAssertionsSigned="${wantAssertionsSigned}">`,
    `    <md:NameIDFormat>${nameIdFormat}</md:NameIDFormat>`,
    `    <md:AssertionConsumerService Binding="${binding}" Location="${options.acsUrl}" index="1" isDefault="true"/>`,
    `  </md:SPSSODescriptor>`,
    `</md:EntityDescriptor>`,
  ].join('\n');
}

export function buildAuthNRequestXml(options: AuthNRequestXmlOptions): string {
  const binding = options.binding ?? AUTH_CONSTANTS.SAML.BINDING_HTTP_POST;
  const nameIdFormat = options.nameIdFormat ?? AUTH_CONSTANTS.SAML.NAMEID_FORMAT_EMAIL;
  const allowCreate = options.allowCreate ?? true;

  return [
    AUTH_CONSTANTS.SAML.XML_PROLOG,
    `<samlp:AuthnRequest xmlns:samlp="${AUTH_CONSTANTS.SAML.NS_PROTOCOL}"`,
    `  xmlns:saml="${AUTH_CONSTANTS.SAML.NS_ASSERTION}"`,
    `  ID="${options.requestId}"`,
    `  Version="${AUTH_CONSTANTS.SAML.PROTOCOL_VERSION}"`,
    `  IssueInstant="${options.issueInstantIso}"`,
    `  Destination="${options.destination}"`,
    `  AssertionConsumerServiceURL="${options.acsUrl}"`,
    `  ProtocolBinding="${binding}">`,
    `  <saml:Issuer>${options.issuer}</saml:Issuer>`,
    `  <samlp:NameIDPolicy Format="${nameIdFormat}" AllowCreate="${allowCreate}"/>`,
    `</samlp:AuthnRequest>`,
  ].join('\n');
}

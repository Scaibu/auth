import type { AuthService } from '../../../features/auth/service';
import {
  handleSignUp,
  handleSignIn,
  handleSignOut,
  handleRefreshToken,
  handleResolveChallenge,
  handleFetchAuditLogs,
  handleCreateOrganization,
  handleListOrganizations,
  handleGetOrganization,
  handleUpdateOrganization,
  handleDeleteOrganization,
  handleSwitchOrganization,
  handleListUsers,
  handleGetUserById,
  handleGetMyProfile,
  handleUpdateMyProfile,
  handleInviteUser,
  handleUpdateUserRole,
  handleGetUserPermissions,
  handleUpdateUserPermissions,
  handleCreateUser,
  handleBlockUser,
  handleUnblockUser,
  handleDeleteUser,
  handleListApiKeys,
  handleRevokeApiKey,
  handleExportMyData,
} from './handlers/auth.handler';
import { handleVerifySession, handleListSessions, handleRevokeSession, handleRevokeOtherSessions } from './handlers/session.handler';
import { handleCreateApiKey, handleVerifyApiKey, handleListPermissions, handleGetApiKeyAllowlist, handleUpdateApiKeyAllowlist } from './handlers/api-key.handler';
import { handleStepUpVerify, handleImpersonateUser, handlePurgeExpired } from './handlers/step-up.handler';
import {
  handleClaimDomain,
  handleVerifyDomain,
  handleListClaimedDomains,
  handleUpdateDomainSettings,
  handleDeleteClaimedDomain,
  handleListBlockedDomains,
  handleAddBlockedDomain,
  handleRemoveBlockedDomain,
} from './handlers/domain.handler';
import {
  handleEvaluatePolicy,
  handleCreateRelation,
  handleDeleteRelation,
  handleListRelations,
} from './handlers/policy.handler';
import {
  handleCreateCustomRole,
  handleGetCustomRole,
  handleListCustomRoles,
  handleUpdateCustomRole,
  handleDeleteCustomRole,
  handleAssignUserCustomRoles,
  handleEvaluatePermissions,
} from './handlers/role.handler';
import {
  handleCreateWebhookSubscription,
  handleListWebhookSubscriptions,
  handleGetWebhookSubscription,
  handleUpdateWebhookSubscription,
  handleDeleteWebhookSubscription,
  handleListWebhookDeliveries,
} from './handlers/webhook.handler';
import {
  handleActivateBreakGlass,
  handleTerminateBreakGlass,
  handleListActiveBreakGlassSessions,
} from './handlers/break-glass.handler';
import {
  handleCreateHoneytoken,
  handleListHoneytokens,
  handleRevokeHoneytoken,
} from './handlers/honeytoken.handler';
import {
  handleSealWormAudit,
  handleListWormAuditArchives,
  handleVerifyWormAuditArchive,
} from './handlers/worm-audit.handler';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../../shared/constants/endpoints';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { UnauthorizedError, ValidationError } from '../../../shared/errors/auth.errors';

export interface RouteContext {
  service: AuthService;
  body?: any;
  headers?: Record<string, string>;
  queryParams?: Record<string, string>;
  authHeader?: string;
  params: Record<string, string>;
}

export interface RouteRule {
  name: string;
  method: string;
  pattern: string;
  requiresAuth?: boolean;
  requiresStepUp?: boolean;
  successStatus?: number;
  successMessage: string;
  handler: (ctx: RouteContext, session?: any) => Promise<any>;
}

export const ROUTE_RULES: RouteRule[] = [
  {
    name: 'root_check',
    method: HTTP_METHODS.GET,
    pattern: '/',
    successMessage: 'Auth Service API v1 is live',
    handler: async () => ({ service: 'auth-service', version: '1.0.0', status: 'healthy' }),
  },
  {
    name: 'health_check',
    method: HTTP_METHODS.GET,
    pattern: '/health',
    successMessage: 'Auth service is healthy',
    handler: async () => ({
      status: 'ok',
      service: 'auth-service',
      version: '1.0.0',
      routesEndpoint: AUTH_ENDPOINTS.ROUTES,
      totalActiveRoutes: ROUTE_RULES.length,
    }),
  },
  {
    name: 'health_check_v1',
    method: HTTP_METHODS.GET,
    pattern: '/api/v1/auth/health',
    successMessage: 'Auth service is healthy',
    handler: async () => ({
      status: 'ok',
      service: 'auth-service',
      version: '1.0.0',
      routesEndpoint: AUTH_ENDPOINTS.ROUTES,
      totalActiveRoutes: ROUTE_RULES.length,
      openapiEndpoint: '/openapi.yaml',
      docsEndpoint: '/docs',
    }),
  },
  {
    name: 'openapi_spec',
    method: HTTP_METHODS.GET,
    pattern: '/openapi.yaml',
    successMessage: 'OpenAPI specification retrieved successfully',
    handler: async () => {
      const fs = await import('fs');
      const path = await import('path');
      const specPath = path.resolve(process.cwd(), 'contracts/openapi/v1.yaml');
      const rawYaml = fs.readFileSync(specPath, 'utf8');
      return { rawYaml, openapiPath: 'contracts/openapi/v1.yaml' };
    },
  },
  {
    name: 'openapi_docs_ui',
    method: HTTP_METHODS.GET,
    pattern: '/docs',
    successMessage: 'OpenAPI documentation UI metadata',
    handler: async () => {
      return {
        title: 'Observability Auth Service API Documentation',
        specUrl: '/openapi.yaml',
        swaggerEditorUrl: 'https://editor.swagger.io/?url=http://localhost:3001/openapi.yaml',
        description: 'OpenAPI 3.0.3 specification defining all request/response envelopes, parameters, and error models.',
      };
    },
  },
  {
    name: 'list_routes',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.ROUTES,
    successMessage: 'Active API route catalog retrieved successfully',
    handler: async () => {
      return {
        totalRoutes: ROUTE_RULES.length,
        routes: ROUTE_RULES.map((r) => ({
          name: r.name,
          method: r.method,
          pattern: r.pattern,
          requiresAuth: Boolean(r.requiresAuth),
          requiresStepUp: Boolean(r.requiresStepUp),
          successStatus: r.successStatus ?? 200,
        })),
      };
    },
  },
  {
    name: 'sign_up',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.SIGN_UP,
    successStatus: 201,
    successMessage: 'User and organization successfully created',
    handler: (ctx) => handleSignUp(ctx.service, ctx.body),
  },
  {
    name: 'sign_in',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.SIGN_IN,
    successMessage: 'User signed in successfully',
    handler: (ctx) => handleSignIn(ctx.service, ctx.body, ctx.headers),
  },
  {
    name: 'sign_out',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.SIGN_OUT,
    requiresAuth: true,
    successMessage: 'User signed out successfully',
    handler: async (ctx) => {
      await handleSignOut(ctx.service, ctx.authHeader);
      return { success: true };
    },
  },
  {
    name: 'refresh_token',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.REFRESH,
    successMessage: 'Token refreshed successfully',
    handler: (ctx) => handleRefreshToken(ctx.service, ctx.body),
  },
  {
    name: 'resolve_challenge',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.CHALLENGE_RESOLVE,
    successMessage: 'Risk challenge resolved successfully',
    handler: (ctx) => handleResolveChallenge(ctx.service, ctx.body, ctx.headers),
  },
  {
    name: 'verify_session',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.SESSION,
    successMessage: 'Session token verified',
    handler: (ctx) => handleVerifySession(ctx.service, ctx.authHeader),
  },
  {
    name: 'list_organizations',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.ORGANIZATIONS,
    requiresAuth: true,
    successMessage: 'Organizations retrieved',
    handler: (ctx, session) => handleListOrganizations(ctx.service, session.sub),
  },
  {
    name: 'create_organization',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.ORGANIZATIONS,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'Organization created successfully',
    handler: (ctx, session) => handleCreateOrganization(ctx.service, ctx.body, session.sub),
  },
  {
    name: 'switch_organization',
    method: HTTP_METHODS.POST,
    pattern: `${AUTH_ENDPOINTS.ORGANIZATIONS}/:id/switch`,
    requiresAuth: true,
    successMessage: 'Organization context switched',
    handler: (ctx, session) => {
      const token = ctx.authHeader?.replace('Bearer ', '') ?? '';
      return handleSwitchOrganization(ctx.service, session.sub, ctx.params['id']!, token);
    },
  },
  {
    name: 'get_organization',
    method: HTTP_METHODS.GET,
    pattern: `${AUTH_ENDPOINTS.ORGANIZATIONS}/:id`,
    successMessage: 'Organization retrieved',
    handler: (ctx) => handleGetOrganization(ctx.service, ctx.params['id']!),
  },
  {
    name: 'update_organization',
    method: HTTP_METHODS.PATCH,
    pattern: `${AUTH_ENDPOINTS.ORGANIZATIONS}/:id`,
    successMessage: 'Organization updated',
    handler: (ctx) => handleUpdateOrganization(ctx.service, ctx.params['id']!, ctx.body),
  },
  {
    name: 'delete_organization',
    method: HTTP_METHODS.DELETE,
    pattern: `${AUTH_ENDPOINTS.ORGANIZATIONS}/:id`,
    requiresAuth: true,
    requiresStepUp: true,
    successMessage: 'Organization soft-deleted with 30-day backup retention',
    handler: (ctx) => handleDeleteOrganization(ctx.service, ctx.params['id']!),
  },
  {
    name: 'get_my_profile',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.USERS_ME,
    requiresAuth: true,
    successMessage: 'User profile retrieved',
    handler: (ctx, session) => handleGetMyProfile(ctx.service, session.sub),
  },
  {
    name: 'update_my_profile',
    method: HTTP_METHODS.PATCH,
    pattern: AUTH_ENDPOINTS.USERS_ME,
    requiresAuth: true,
    successMessage: 'User profile updated',
    handler: (ctx, session) => handleUpdateMyProfile(ctx.service, session.sub, ctx.body),
  },
  {
    name: 'get_my_data_export',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.USERS_ME_EXPORT,
    requiresAuth: true,
    successMessage: 'User data exported successfully',
    handler: (ctx, session) => handleExportMyData(ctx.service, session.sub),
  },
  {
    name: 'list_users',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.USERS,
    requiresAuth: true,
    successMessage: 'Members retrieved',
    handler: (ctx, session) => handleListUsers(ctx.service, session.org.org_id),
  },
  {
    name: 'create_user',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.USERS,
    successStatus: 201,
    successMessage: 'User created in target organization with specific permissions',
    handler: (ctx) => handleCreateUser(ctx.service, ctx.body),
  },
  {
    name: 'invite_user',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.USERS_INVITE,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'User invited to organization',
    handler: (ctx, session) => handleInviteUser(ctx.service, ctx.body, session.org.org_id, session.org.org_name),
  },
  {
    name: 'block_user',
    method: HTTP_METHODS.POST,
    pattern: `${AUTH_ENDPOINTS.USERS}/:id/block`,
    successMessage: 'User blocked successfully',
    handler: (ctx) => handleBlockUser(ctx.service, ctx.params['id']!),
  },
  {
    name: 'unblock_user',
    method: HTTP_METHODS.DELETE,
    pattern: `${AUTH_ENDPOINTS.USERS}/:id/unblock`,
    successMessage: 'User unblocked successfully',
    handler: (ctx) => handleUnblockUser(ctx.service, ctx.params['id']!),
  },
  {
    name: 'update_user_role',
    method: HTTP_METHODS.PATCH,
    pattern: `${AUTH_ENDPOINTS.USERS}/:id/role`,
    requiresAuth: true,
    successMessage: 'User role updated',
    handler: async (ctx, session) => {
      const targetRole = ctx.body?.role;
      if (targetRole === 'admin' || targetRole === 'owner') {
        const reauthToken = ctx.headers?.[AUTH_CONSTANTS.HEADERS.REAUTH_TOKEN] ?? ctx.headers?.[AUTH_CONSTANTS.HEADERS.REAUTH_TOKEN_CAMEL];
        ctx.service.assertStepUp(session.sub, reauthToken);
      }
      await handleUpdateUserRole(ctx.service, ctx.params['id']!, ctx.body);
      return null;
    },
  },
  {
    name: 'get_user_permissions',
    method: HTTP_METHODS.GET,
    pattern: `${AUTH_ENDPOINTS.USERS}/:id/permissions`,
    successMessage: 'User permissions retrieved',
    handler: (ctx) => handleGetUserPermissions(ctx.service, ctx.params['id']!),
  },
  {
    name: 'update_user_permissions',
    method: HTTP_METHODS.PATCH,
    pattern: `${AUTH_ENDPOINTS.USERS}/:id/permissions`,
    successMessage: 'User permissions updated',
    handler: async (ctx) => {
      await handleUpdateUserPermissions(ctx.service, ctx.params['id']!, ctx.body);
      return null;
    },
  },
  {
    name: 'get_user_by_id',
    method: HTTP_METHODS.GET,
    pattern: `${AUTH_ENDPOINTS.USERS}/:id`,
    successMessage: 'User retrieved',
    handler: (ctx) => handleGetUserById(ctx.service, ctx.params['id']!),
  },
  {
    name: 'delete_user',
    method: HTTP_METHODS.DELETE,
    pattern: `${AUTH_ENDPOINTS.USERS}/:id`,
    successMessage: 'User soft-deleted with 30-day backup retention',
    handler: (ctx) => handleDeleteUser(ctx.service, ctx.params['id']!),
  },
  {
    name: 'list_api_keys',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.API_KEYS,
    requiresAuth: true,
    successMessage: 'API keys retrieved',
    handler: (ctx, session) => handleListApiKeys(ctx.service, session.org.org_id),
  },
  {
    name: 'create_api_key',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.API_KEYS,
    successStatus: 201,
    successMessage: 'API key successfully created',
    handler: (ctx, session) => {
      const keyType = ctx.body?.key_type;
      if (keyType === 'super_secret') {
        const userId = session?.sub ?? session?.payload?.sub;
        if (!userId) {
          throw new UnauthorizedError('Authentication required to create super_secret keys');
        }
        const reauthToken = ctx.headers?.[AUTH_CONSTANTS.HEADERS.REAUTH_TOKEN] ?? ctx.headers?.[AUTH_CONSTANTS.HEADERS.REAUTH_TOKEN_CAMEL];
        ctx.service.assertStepUp(userId, reauthToken);
      }
      return handleCreateApiKey(ctx.service, ctx.body);
    },
  },
  {
    name: 'verify_api_key',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.API_KEYS_VERIFY,
    successMessage: 'API key verified',
    handler: (ctx) => handleVerifyApiKey(ctx.service, ctx.body),
  },
  {
    name: 'get_api_key_allowlist',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.API_KEY_ALLOWLIST,
    requiresAuth: true,
    successMessage: 'API key IP allowlist retrieved',
    handler: (ctx) => handleGetApiKeyAllowlist(ctx.service, ctx.params['id']!),
  },
  {
    name: 'update_api_key_allowlist',
    method: HTTP_METHODS.PATCH,
    pattern: AUTH_ENDPOINTS.API_KEY_ALLOWLIST,
    requiresAuth: true,
    successMessage: 'API key IP allowlist updated',
    handler: (ctx) => handleUpdateApiKeyAllowlist(ctx.service, ctx.params['id']!, ctx.body),
  },
  {
    name: 'revoke_api_key',
    method: HTTP_METHODS.POST,
    pattern: `${AUTH_ENDPOINTS.API_KEYS}/:id/revoke`,
    successMessage: 'API key revoked',
    handler: async (ctx) => {
      await handleRevokeApiKey(ctx.service, ctx.params['id']!);
      return null;
    },
  },
  {
    name: 'list_permissions',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.PERMISSIONS,
    successMessage: 'System permissions retrieved',
    handler: (ctx) => handleListPermissions(ctx.service),
  },
  {
    name: 'fetch_audit_logs',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.AUDIT_LOGS,
    requiresAuth: true,
    successMessage: 'Audit logs retrieved',
    handler: (ctx, session) => handleFetchAuditLogs(ctx.service, session.sub, ctx.queryParams),
  },
  {
    name: 'step_up_verify',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.STEP_UP_VERIFY,
    requiresAuth: true,
    successMessage: 'Step-up authentication successful',
    handler: (ctx, session) => handleStepUpVerify(ctx, session),
  },
  {
    name: 'admin_impersonate',
    method: HTTP_METHODS.POST,
    pattern: `${AUTH_ENDPOINTS.ADMIN_IMPERSONATE}/:id`,
    requiresAuth: true,
    requiresStepUp: true,
    successMessage: 'User impersonated successfully',
    handler: (ctx, session) => handleImpersonateUser(ctx, session),
  },
  {
    name: 'admin_purge_expired',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.ADMIN_PURGE_EXPIRED,
    requiresAuth: true,
    requiresStepUp: true,
    successMessage: 'Retention purge completed successfully',
    handler: (ctx, session) => handlePurgeExpired(ctx, session),
  },
  {
    name: 'user_shred_pii',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.USER_SHRED,
    requiresAuth: true,
    requiresStepUp: true,
    successMessage: 'User PII and cryptographic DEK permanently shredded (GDPR Article 17)',
    handler: async (ctx) => {
      const targetUserId = ctx.params?.id ?? '';
      if (!targetUserId) {
        throw new ValidationError('User id parameter is required');
      }
      return ctx.service.shredUserPii(targetUserId);
    },
  },
  {
    name: 'list_sessions',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.SESSIONS,
    requiresAuth: true,
    successMessage: 'Active sessions retrieved successfully',
    handler: (ctx, session) => handleListSessions(ctx.service, session.sub, ctx.headers?.['x-session-family']),
  },
  {
    name: 'revoke_session',
    method: HTTP_METHODS.DELETE,
    pattern: `${AUTH_ENDPOINTS.SESSIONS}/:id`,
    requiresAuth: true,
    successMessage: 'Session successfully terminated',
    handler: (ctx, session) => handleRevokeSession(ctx.service, session.sub, ctx.params?.id ?? ''),
  },
  {
    name: 'revoke_other_sessions',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.SESSIONS,
    requiresAuth: true,
    successMessage: 'All other sessions successfully terminated',
    handler: (ctx, session) => handleRevokeOtherSessions(ctx.service, session.sub, ctx.headers?.['x-session-family']),
  },
  {
    name: 'claim_domain',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.DOMAINS,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'Domain claim registered successfully',
    handler: (ctx, session) => handleClaimDomain(ctx.service, ctx.body, session),
  },
  {
    name: 'list_claimed_domains',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.DOMAINS,
    requiresAuth: true,
    successMessage: 'Claimed domains retrieved successfully',
    handler: (ctx, session) => handleListClaimedDomains(ctx.service, session),
  },
  {
    name: 'verify_domain',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.DOMAINS_VERIFY,
    requiresAuth: true,
    successMessage: 'Domain DNS verification executed',
    handler: (ctx, session) => handleVerifyDomain(ctx.service, ctx.params?.domainId ?? '', session),
  },
  {
    name: 'update_domain_settings',
    method: HTTP_METHODS.PATCH,
    pattern: AUTH_ENDPOINTS.DOMAINS_ITEM,
    requiresAuth: true,
    successMessage: 'Domain settings updated successfully',
    handler: (ctx, session) => handleUpdateDomainSettings(ctx.service, ctx.params?.domainId ?? '', ctx.body, session),
  },
  {
    name: 'delete_claimed_domain',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.DOMAINS_ITEM,
    requiresAuth: true,
    successMessage: 'Domain claim deleted successfully',
    handler: (ctx, session) => handleDeleteClaimedDomain(ctx.service, ctx.params?.domainId ?? '', session),
  },
  {
    name: 'admin_list_blocked_domains',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.ADMIN_BLOCKED_DOMAINS,
    requiresAuth: true,
    successMessage: 'Blocked domains retrieved successfully',
    handler: (ctx, session) => handleListBlockedDomains(ctx.service, session),
  },
  {
    name: 'admin_add_blocked_domain',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.ADMIN_BLOCKED_DOMAINS,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'Blocked domain added successfully',
    handler: (ctx, session) => handleAddBlockedDomain(ctx.service, ctx.body, session),
  },
  {
    name: 'admin_remove_blocked_domain',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.ADMIN_BLOCKED_DOMAIN_ITEM,
    requiresAuth: true,
    successMessage: 'Blocked domain removed successfully',
    handler: (ctx, session) => handleRemoveBlockedDomain(ctx.service, ctx.params?.domain ?? '', session),
  },
  {
    name: 'policies_evaluate',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.POLICIES_EVALUATE,
    requiresAuth: true,
    successMessage: 'Policy evaluation decision computed successfully',
    handler: (ctx, session) => handleEvaluatePolicy(ctx.service, ctx.body, session),
  },
  {
    name: 'policies_create_relation',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.POLICIES_RELATIONS,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'Relationship tuple created successfully',
    handler: (ctx, session) => handleCreateRelation(ctx.service, ctx.body, session),
  },
  {
    name: 'policies_delete_relation',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.POLICIES_RELATIONS,
    requiresAuth: true,
    successMessage: 'Relationship tuple deleted successfully',
    handler: (ctx, session) => handleDeleteRelation(ctx.service, ctx.body, session),
  },
  {
    name: 'policies_list_relations',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.POLICIES_RELATIONS,
    requiresAuth: true,
    successMessage: 'Relationship tuples retrieved successfully',
    handler: (ctx, session) => handleListRelations(ctx.service, ctx.queryParams, session),
  },
  {
    name: 'custom_roles_create',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.ROLES,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'Custom enterprise role created successfully',
    handler: (ctx, session) => handleCreateCustomRole(ctx.service, ctx.body, session!),
  },
  {
    name: 'custom_roles_list',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.ROLES,
    requiresAuth: true,
    successMessage: 'Custom roles retrieved successfully',
    handler: (ctx, session) => handleListCustomRoles(ctx.service, session!),
  },
  {
    name: 'custom_roles_get',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.ROLES_ITEM,
    requiresAuth: true,
    successMessage: 'Custom role retrieved successfully',
    handler: (ctx, session) => handleGetCustomRole(ctx.service, ctx.params.id!, session!),
  },
  {
    name: 'custom_roles_update',
    method: HTTP_METHODS.PUT,
    pattern: AUTH_ENDPOINTS.ROLES_ITEM,
    requiresAuth: true,
    successMessage: 'Custom role updated successfully',
    handler: (ctx, session) => handleUpdateCustomRole(ctx.service, ctx.params.id!, ctx.body, session!),
  },
  {
    name: 'custom_roles_delete',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.ROLES_ITEM,
    requiresAuth: true,
    successMessage: 'Custom role deleted successfully',
    handler: (ctx, session) => handleDeleteCustomRole(ctx.service, ctx.params.id!, session!),
  },
  {
    name: 'user_custom_roles_assign',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.USER_ROLES,
    requiresAuth: true,
    successMessage: 'User custom roles assigned successfully',
    handler: (ctx, session) => handleAssignUserCustomRoles(ctx.service, ctx.params.userId!, ctx.body, session!),
  },
  {
    name: 'permissions_bitmask_evaluate',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.PERMISSIONS_EVALUATE,
    requiresAuth: false,
    successMessage: 'Permissions evaluated successfully',
    handler: (ctx) => handleEvaluatePermissions(ctx.service, ctx.body),
  },
  {
    name: 'webhook_create_subscription',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.WEBHOOK_SUBSCRIPTIONS,
    requiresAuth: true,
    successMessage: 'Webhook subscription created successfully',
    handler: (ctx, session) => handleCreateWebhookSubscription(ctx.service, ctx.body, session),
  },
  {
    name: 'webhook_list_subscriptions',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.WEBHOOK_SUBSCRIPTIONS,
    requiresAuth: true,
    successMessage: 'Webhook subscriptions retrieved successfully',
    handler: (ctx, session) => handleListWebhookSubscriptions(ctx.service, session),
  },
  {
    name: 'webhook_get_subscription',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.WEBHOOK_SUBSCRIPTIONS_ITEM,
    requiresAuth: true,
    successMessage: 'Webhook subscription retrieved successfully',
    handler: (ctx, session) => handleGetWebhookSubscription(ctx.service, ctx.params.id ?? '', session),
  },
  {
    name: 'webhook_update_subscription',
    method: HTTP_METHODS.PATCH,
    pattern: AUTH_ENDPOINTS.WEBHOOK_SUBSCRIPTIONS_ITEM,
    requiresAuth: true,
    successMessage: 'Webhook subscription updated successfully',
    handler: (ctx, session) => handleUpdateWebhookSubscription(ctx.service, ctx.params.id ?? '', ctx.body, session),
  },
  {
    name: 'webhook_delete_subscription',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.WEBHOOK_SUBSCRIPTIONS_ITEM,
    requiresAuth: true,
    successMessage: 'Webhook subscription deleted successfully',
    handler: (ctx, session) => handleDeleteWebhookSubscription(ctx.service, ctx.params.id ?? '', session),
  },
  {
    name: 'webhook_list_deliveries',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.WEBHOOK_DELIVERIES,
    requiresAuth: true,
    successMessage: 'Webhook deliveries retrieved successfully',
    handler: (ctx, session) => handleListWebhookDeliveries(ctx.service, ctx.params.id ?? '', session),
  },
  {
    name: 'break_glass_activate',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.BREAK_GLASS_ACTIVATE,
    requiresAuth: true,
    requiresStepUp: true,
    successMessage: 'Emergency break-glass session activated successfully',
    handler: (ctx, session) => handleActivateBreakGlass(ctx.service, ctx.body, session),
  },
  {
    name: 'break_glass_terminate',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.BREAK_GLASS_TERMINATE,
    requiresAuth: true,
    requiresStepUp: true,
    successMessage: 'Emergency break-glass session terminated successfully',
    handler: (ctx, session) => handleTerminateBreakGlass(ctx.service, ctx.params.id ?? '', ctx.body, session),
  },
  {
    name: 'break_glass_list_active',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.BREAK_GLASS_ACTIVE,
    requiresAuth: true,
    successMessage: 'Active emergency break-glass sessions retrieved successfully',
    handler: (ctx, session) => handleListActiveBreakGlassSessions(ctx.service, session),
  },
  {
    name: 'honeytoken_create',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.HONEYTOKENS,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'Honeytoken canary secret created successfully',
    handler: (ctx, session) => handleCreateHoneytoken(ctx.service, ctx.body, session),
  },
  {
    name: 'honeytoken_list',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.HONEYTOKENS,
    requiresAuth: true,
    successMessage: 'Honeytokens retrieved successfully',
    handler: (ctx, session) => handleListHoneytokens(ctx.service, session),
  },
  {
    name: 'honeytoken_revoke',
    method: HTTP_METHODS.DELETE,
    pattern: AUTH_ENDPOINTS.HONEYTOKEN_REVOKE,
    requiresAuth: true,
    successMessage: 'Honeytoken revoked successfully',
    handler: (ctx, session) => handleRevokeHoneytoken(ctx.service, ctx.params.id ?? '', session),
  },
  {
    name: 'worm_audit_seal',
    method: HTTP_METHODS.POST,
    pattern: AUTH_ENDPOINTS.WORM_AUDIT_SEAL,
    requiresAuth: true,
    successStatus: 201,
    successMessage: 'Audit log segment sealed in immutable WORM archive',
    handler: (ctx, session) => handleSealWormAudit(ctx.service, ctx.body, session),
  },
  {
    name: 'worm_audit_list',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.WORM_AUDIT_ARCHIVES,
    requiresAuth: true,
    successMessage: 'WORM audit archives retrieved successfully',
    handler: (ctx, session) => handleListWormAuditArchives(ctx.service, session),
  },
  {
    name: 'worm_audit_verify',
    method: HTTP_METHODS.GET,
    pattern: AUTH_ENDPOINTS.WORM_AUDIT_VERIFY,
    requiresAuth: true,
    successMessage: 'WORM audit archive Merkle integrity verified',
    handler: (ctx, session) => handleVerifyWormAuditArchive(ctx.service, ctx.params.id ?? '', session),
  },
];



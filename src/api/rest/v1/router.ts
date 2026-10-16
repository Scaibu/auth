import { SpanStatusCode } from '@chief-strategist-j/shared-infra';
import { HTTP_CONSTANTS } from '@chief-strategist-j/shared-infra/http';
import type { AuthService } from '../../../features/auth/service';
import { handleVerifySession } from './handlers/session.handler';
import { withSpan } from '../../../infra/tracing/tracer';
import { AUTH_CONSTANTS } from '../../../shared/constants/auth.constants';
import { UnauthorizedError } from '../../../shared/errors/auth.errors';
import { createSuccessResponse, createErrorResponse, type StandardApiResponse } from '../../../shared/errors/error-handler';
import { ROUTE_RULES, type RouteContext, type RouteRule } from './route.rules';
import { computeSecurityHeaders } from '../../../shared/utils/security-headers.engine';
import { loadSecurityHeadersConfig, type SecurityHeadersConfig } from '../../../config/security-headers.config';

function compilePathPattern(pattern: string): { regex: RegExp; paramNames: string[] } {
  const paramNames: string[] = [];
  const regexStr = pattern.replace(/:([a-zA-Z0-9_]+)/g, (_, name) => {
    paramNames.push(name);
    return '([^/]+)';
  });
  return { regex: new RegExp(`^${regexStr}$`), paramNames };
}

interface CompiledRouteRule extends RouteRule {
  regex: RegExp;
  paramNames: string[];
}

export class AuthRestV1Router {
  private readonly compiledRules: CompiledRouteRule[];
  private readonly securityHeadersConfig: SecurityHeadersConfig;

  constructor(
    private readonly service: AuthService,
    securityHeadersConfig?: SecurityHeadersConfig
  ) {
    this.securityHeadersConfig = securityHeadersConfig ?? loadSecurityHeadersConfig();
    this.compiledRules = ROUTE_RULES.map((rule) => {
      const { regex, paramNames } = compilePathPattern(rule.pattern);
      return { ...rule, regex, paramNames };
    });
  }

  private findMatchingRule(method: string, path: string): { rule: CompiledRouteRule; params: Record<string, string> } | null {
    for (const rule of this.compiledRules) {
      if (rule.method !== method) continue;
      const match = rule.regex.exec(path);
      if (match) {
        const params: Record<string, string> = {};
        rule.paramNames.forEach((name, index) => {
          params[name] = decodeURIComponent(match[index + 1]!);
        });
        return { rule, params };
      }
    }
    return null;
  }

  async route(method: string, path: string, body?: unknown, headers?: Record<string, string>, queryParams?: Record<string, string>): Promise<{ statusCode: number; payload: StandardApiResponse<unknown>; headers?: Record<string, string> }> {
    const startTimeMs = performance.now();
    return withSpan(`REST ${method} ${path}`, async (span) => {
      span.setAttribute('http.method', method);
      span.setAttribute('http.target', path);

      const requestId = headers?.[HTTP_CONSTANTS.HEADER_X_REQUEST_ID] ?? `req_${Date.now()}`;
      const correlationId = headers?.[HTTP_CONSTANTS.HEADER_X_CORRELATION_ID] ?? requestId;
      const causationId = headers?.['x-causation-id'];
      const tenantId = headers?.[HTTP_CONSTANTS.HEADER_X_TENANT_ID];
      const clientId = headers?.['x-client-id'];
      const traceparent = headers?.[HTTP_CONSTANTS.HEADER_TRACEPARENT];

      span.setAttribute('x-request-id', requestId);
      span.setAttribute('request_id', requestId);
      span.setAttribute('x-correlation-id', correlationId);
      span.setAttribute('correlation_id', correlationId);
      if (causationId) span.setAttribute('x-causation-id', causationId);
      if (tenantId) {
        span.setAttribute('x-tenant-id', tenantId);
        span.setAttribute('tenant_id', tenantId);
      }
      if (clientId) span.setAttribute('x-client-id', clientId);
      if (traceparent) span.setAttribute(HTTP_CONSTANTS.HEADER_TRACEPARENT, traceparent);

      if (body && typeof body === 'object') {
        const b = body as Record<string, unknown>;
        if (typeof b['email'] === 'string') {
          span.setAttribute('user.email', b['email']);
          span.setAttribute('user_email', b['email']);
          span.setAttribute('email', b['email']);
        }
        if (typeof b['org_id'] === 'string') {
          span.setAttribute('org.id', b['org_id']);
          span.setAttribute('org_id', b['org_id']);
        }
        if (typeof b['organization_name'] === 'string') {
          span.setAttribute('org.name', b['organization_name']);
          span.setAttribute('org_name', b['organization_name']);
        }
      }

      const getMetaOptions = () => ({
        requestId,
        correlationId,
        causationId,
        timestamp: new Date().toISOString(),
        executionTimeMs: Math.round(performance.now() - startTimeMs),
        apiVersion: '1.0.0',
      });

      try {
        const matched = this.findMatchingRule(method, path);
        if (!matched) {
          throw new Error(`Route not found: ${method} ${path}`);
        }

        const { rule, params } = matched;
        span.setAttribute('route.name', rule.name);

        const authHeader = headers?.[AUTH_CONSTANTS.HEADERS.AUTHORIZATION] ?? headers?.[AUTH_CONSTANTS.HEADERS.AUTHORIZATION_CAMEL];
        let session: any = undefined;

        if (authHeader) {
          const rawToken = authHeader.replace(/^Bearer\s+/i, '').trim();
          if (rawToken.startsWith(AUTH_CONSTANTS.HONEYTOKEN.DEFAULT_PREFIX)) {
            const clientIp = headers?.[AUTH_CONSTANTS.HEADERS.FORWARDED_FOR]?.split(',')[0]?.trim() || '127.0.0.1';
            const userAgent = headers?.[AUTH_CONSTANTS.HEADERS.USER_AGENT] || 'unknown';
            await this.service.honeytokenService.inspectAndTrip(rawToken, {
              ip: clientIp,
              userAgent,
            });
            throw new UnauthorizedError('Invalid credentials');
          }
        }

        if (rule.requiresAuth || authHeader) {
          try {
            session = await handleVerifySession(this.service, authHeader);
            const sub = session?.sub ?? session?.payload?.sub;
            const orgId = session?.org?.org_id ?? session?.payload?.org?.org_id;
            if (sub) span.setAttribute('user.id', sub);
            if (orgId) span.setAttribute('org.id', orgId);

            const cnf = session?.cnf ?? session?.payload?.cnf;
            const expectedThumbprint = cnf?.[AUTH_CONSTANTS.MTLS.CNF_X5T_S256_KEY];
            if (expectedThumbprint) {
              const presentedCert = headers?.['x-client-cert'] ||
                headers?.['X-Client-Cert'] ||
                headers?.['x-ssl-client-cert'] ||
                headers?.['X-SSL-Client-Cert'] ||
                headers?.['ssl-client-cert'];

              if (!presentedCert) {
                throw new UnauthorizedError('Certificate-bound access token requires presented client certificate');
              }
            }
          } catch (sessionErr) {
            if (rule.requiresAuth) throw sessionErr;
          }
        }

        if (rule.requiresStepUp) {
          const reauthToken = headers?.[AUTH_CONSTANTS.HEADERS.REAUTH_TOKEN] ?? headers?.[AUTH_CONSTANTS.HEADERS.REAUTH_TOKEN_CAMEL];
          const userId = session?.sub ?? session?.payload?.sub;
          if (!userId) {
            throw new UnauthorizedError('Authentication required for step-up enforcement');
          }
          this.service.assertStepUp(userId, reauthToken);
        }

        const { headers: secHeaders, nonce: cspNonce } = computeSecurityHeaders(this.securityHeadersConfig);
        span.setAttribute('security.csp_nonce', cspNonce);

        const ctx: RouteContext = {
          service: this.service,
          body,
          headers,
          queryParams,
          authHeader,
          params,
        };

        const resultData = await rule.handler(ctx, session);
        const statusCode = rule.successStatus ?? 200;

        span.setAttribute('http.status_code', statusCode);
        return {
          statusCode,
          payload: createSuccessResponse(resultData, rule.successMessage, getMetaOptions(), statusCode),
          headers: {
            ...secHeaders,
          },
        };
      } catch (err: unknown) {
        const errorRes = createErrorResponse(err, getMetaOptions());
        const { headers: secHeaders } = computeSecurityHeaders(this.securityHeadersConfig);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: errorRes.payload.message,
        });
        if (err instanceof Error) {
          span.recordException(err);
        } else {
          span.recordException(new Error(errorRes.payload.message));
        }
        span.setAttribute('error', true);
        span.setAttribute('error.code', errorRes.payload.error?.code ?? 'UNKNOWN_ERROR');
        span.setAttribute('error.message', errorRes.payload.message);
        span.setAttribute('http.status_code', errorRes.statusCode);
        return {
          statusCode: errorRes.statusCode,
          payload: errorRes.payload,
          headers: {
            ...secHeaders,
            ...(errorRes.headers || {}),
          },
        };
      }
    });
  }
}

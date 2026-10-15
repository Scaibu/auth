/**
 * @file base-rest-mailer.adapter.ts
 * @description Abstract Base REST Mailer Adapter orchestrating shared HTTP client,
 * fail-fast envelope validation, credentials checks, and centralized error handling.
 *
 * OVERALL ALGORITHM:
 * 1. Initialize with shared ScalableHttpClient facade or optional custom client.
 * 2. Execute fail-fast envelope integrity verification prior to resource allocation.
 * 3. Execute fail-fast credentials verification prior to outbound network requests.
 * 4. Delegate payload construction to provider-specific subclass implementation.
 * 5. Dispatch HTTP POST via resilient HTTP client and parse response into SendMailResult.
 * 6. Centralize error trapping and format standardized diagnostic messages.
 */

import { httpClient } from '@chief-strategist-j/shared-infra/http';
import type { MailerPort, EmailMessage, SendMailResult } from '../../../shared/ports/mailer.port';
import { validateEmailMessage, formatMailerError } from '../../../shared/utils/mailer.util';

export interface IMailerHttpClient {
  get<T = any>(url: string, headers?: Record<string, string>, options?: any): Promise<{ data: T; status: number; headers?: any }>;
  post<T = any>(url: string, body?: unknown, headers?: Record<string, string>, options?: any): Promise<{ data: T; status: number; headers?: any }>;
}

export interface PreparedRequest {
  url: string;
  body?: unknown;
  headers?: Record<string, string>;
  options?: Record<string, any>;
}

import { withSpan } from '../../tracing/tracer';
import { SpanKind } from '@chief-strategist-j/shared-infra/tracing';

export abstract class BaseRestMailerAdapter implements MailerPort {
  protected readonly httpClient: IMailerHttpClient;
  abstract readonly providerName: string;

  constructor(customClient?: IMailerHttpClient) {
    this.httpClient = customClient ?? (httpClient as unknown as IMailerHttpClient);
  }

  protected abstract validateCredentials(): { isValid: boolean; error?: string };

  protected abstract buildPayload(message: EmailMessage): Promise<PreparedRequest> | PreparedRequest;

  protected abstract parseSendResponse(response: { data: any; status: number; headers?: any }): SendMailResult;

  abstract verify(): Promise<boolean>;

  public async send(message: EmailMessage): Promise<SendMailResult> {
    return withSpan(`mailer.send.${this.providerName.toLowerCase()}`, async (span) => {
      span.setAttribute('mailer.provider', this.providerName);
      span.setAttribute('mailer.to', message.to);
      span.setAttribute('mailer.subject', message.subject);

      const messageValidation = validateEmailMessage(message);
      if (!messageValidation.isValid) {
        return { success: false, error: messageValidation.error };
      }

      const credentialValidation = this.validateCredentials();
      if (!credentialValidation.isValid) {
        return { success: false, error: credentialValidation.error };
      }

      try {
        const prepared = await this.buildPayload(message);
        const response = await this.httpClient.post(
          prepared.url,
          prepared.body,
          prepared.headers,
          prepared.options
        );

        const result = this.parseSendResponse(response);
        span.setAttribute('mailer.success', result.success);
        return result;
      } catch (err: unknown) {
        if (err instanceof Error) span.recordException(err);
        return {
          success: false,
          error: formatMailerError(this.providerName, err),
        };
      }
    }, { kind: SpanKind.CLIENT });
  }
}

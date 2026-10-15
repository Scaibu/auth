export interface WebhookConfig {
  readonly toleranceMs: number;
  readonly defaultMaxRetries: number;
}

export const DEFAULT_WEBHOOK_CONFIG: WebhookConfig = Object.freeze({
  toleranceMs: 300000,
  defaultMaxRetries: 5,
});

export function loadWebhookConfig(): WebhookConfig {
  return Object.freeze({
    toleranceMs: parseInt(
      process.env.AUTH_WEBHOOK_TOLERANCE_MS || String(DEFAULT_WEBHOOK_CONFIG.toleranceMs),
      10,
    ),
    defaultMaxRetries: parseInt(
      process.env.AUTH_WEBHOOK_DEFAULT_RETRIES || String(DEFAULT_WEBHOOK_CONFIG.defaultMaxRetries),
      10,
    ),
  });
}

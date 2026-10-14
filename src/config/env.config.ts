import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSecurityConfig, type RateLimitConfig, type SessionDenylistConfig, type SecurityLimitsConfig } from './security.config';
import { loadMailerConfig, type MailerConfig, type SesMailerConfig, type SendgridMailerConfig, type SmtpMailerConfig, type MailerProvider } from './mailer.config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../../.env');

if (typeof process.loadEnvFile === 'function') {
  try {
    if (fs.existsSync(envPath)) {
      process.loadEnvFile(envPath);
    } else {
      process.loadEnvFile();
    }
  } catch {}
}

function getRequiredEnv(key: string): string {
  const value = process.env[key];
  if (value === undefined || value.trim() === '') {
    throw new Error(`Missing required environment variable: ${key} does not exist`);
  }
  return value;
}

export const AUTH_CONFIG = Object.freeze({
  db: {
    host: getRequiredEnv('AUTH_DB_HOST'),
    port: parseInt(getRequiredEnv('AUTH_DB_PORT'), 10),
    user: getRequiredEnv('AUTH_DB_USER'),
    password: getRequiredEnv('AUTH_DB_PASSWORD'),
    name: getRequiredEnv('AUTH_DB_NAME'),
    url: getRequiredEnv('DATABASE_URL'),
    superUser: process.env.AUTH_DB_SUPER_USER,
    superPassword: process.env.AUTH_DB_SUPER_PASSWORD,
    superDatabase: process.env.AUTH_DB_SUPER_DB,
  },
  redis: {
    host: getRequiredEnv('AUTH_REDIS_HOST'),
    port: parseInt(getRequiredEnv('AUTH_REDIS_PORT'), 10),
    password: getRequiredEnv('AUTH_REDIS_PASSWORD'),
    url: getRequiredEnv('REDIS_URL'),
  },
  kafka: {
    brokers: getRequiredEnv('KAFKA_BROKERS'),
    clientId: getRequiredEnv('KAFKA_CLIENT_ID'),
    securityProtocol: getRequiredEnv('KAFKA_SECURITY_PROTOCOL'),
  },
  otel: {
    endpoint: getRequiredEnv('OTEL_EXPORTER_OTLP_ENDPOINT'),
    grpcEndpoint: getRequiredEnv('OTEL_EXPORTER_OTLP_GRPC_ENDPOINT'),
    serviceName: getRequiredEnv('OTEL_SERVICE_NAME'),
    insecure: getRequiredEnv('OTEL_EXPORTER_OTLP_INSECURE') === 'true',
  },
  serviceRegistry: {
    url: getRequiredEnv('SERVICE_REGISTRY_URL'),
  },
  server: {
    port: parseInt(process.env.PORT || '3001', 10),
    host: process.env.HOST || 'localhost',
    protocol: process.env.PROTOCOL || 'http',
    useMockDb: process.env.USE_MOCK_DB === 'true',
    useMockRedis: process.env.USE_MOCK_REDIS === 'true' || process.env.USE_MOCK_DB === 'true',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'super-secure-production-auth-jwt-secret-key-replace-in-env-file-minimum-32-chars!',
  },
  security: loadSecurityConfig(),
  mailer: loadMailerConfig(),
});

export type { RateLimitConfig, SessionDenylistConfig, SecurityLimitsConfig, MailerConfig, SesMailerConfig, SendgridMailerConfig, SmtpMailerConfig, MailerProvider };
export const authEnv = AUTH_CONFIG;
export default AUTH_CONFIG;

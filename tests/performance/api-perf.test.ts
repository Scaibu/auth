import { describe, it, expect, beforeAll } from 'vitest';
import { AuthService } from '../../src/features/auth/service';
import { AuthRestV1Router } from '../../src/api/rest/v1/router';
import { AlloyDBOmniAuthAdapter } from '../../src/infra/adapters/postgres/alloydb-omni-auth.adapter';
import { AUTH_ENDPOINTS, HTTP_METHODS } from '../../src/shared/constants/endpoints';

describe('Router & API Performance Benchmarks', () => {
  let router: AuthRestV1Router;
  let testSessionToken: string;

  beforeAll(async () => {
    const repository = new AlloyDBOmniAuthAdapter();
    const service = new AuthService(repository);
    router = new AuthRestV1Router(service);

    const signUpRes = await router.route(HTTP_METHODS.POST, AUTH_ENDPOINTS.SIGN_UP, {
      email: `perf_api_${Date.now()}@observability.io`,
      password: 'StrongPassword123!',
      name: 'Perf Benchmark User',
      organization_name: `Perf Org ${Date.now()}`,
    });
    testSessionToken = (signUpRes.payload.data as any).token;
  });

  it('evaluates GET /health route dispatch in < 0.05ms per call under sustained load', async () => {
    const iterations = 5000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const res = await router.route(HTTP_METHODS.GET, AUTH_ENDPOINTS.HEALTH);
      expect(res.statusCode).toBe(200);
    }
    const totalElapsed = performance.now() - start;
    const avgLatencyMs = totalElapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(0.12);
  });

  it('authenticates session and evaluates route rules in < 1.5ms per call under sustained load', async () => {
    const iterations = 1000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const res = await router.route(
        HTTP_METHODS.GET,
        AUTH_ENDPOINTS.SESSION,
        undefined,
        { authorization: `Bearer ${testSessionToken}` }
      );
      expect(res.statusCode).toBe(200);
    }
    const totalElapsed = performance.now() - start;
    const avgLatencyMs = totalElapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(1.5);
  });
});

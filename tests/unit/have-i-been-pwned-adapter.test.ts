import { describe, it, expect, vi, afterEach } from 'vitest';
import { HaveIBeenPwnedAdapter } from '../../src/infra/adapters/security/pwned-passwords.adapter';
import { httpClient } from '@chief-strategist-j/shared-infra/http';

describe('HaveIBeenPwnedAdapter (k-Anonymity mathematical isolation)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('correctly detects pwned password matching returned suffix', async () => {
    const mockResponseText = [
      '0018A45C4D1def:2',
      '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3860349',
      '1E4C9B93F3F0682250B6CF8331B7EE68FD9:1',
    ].join('\r\n');

    vi.spyOn(httpClient, 'get').mockResolvedValue({
      data: mockResponseText,
      status: 200,
      headers: {},
    } as any);

    const adapter = new HaveIBeenPwnedAdapter({
      baseUrl: 'https://api.pwnedpasswords.com/range',
      timeoutMs: 1000,
      userAgent: 'llm-observability-auth/1.0.0',
    });
    const isPwned = await adapter.checkIsPasswordPwned('password');

    expect(isPwned).toBe(true);
    expect(httpClient.get).toHaveBeenCalledWith(
      'https://api.pwnedpasswords.com/range/5BAA6',
      expect.objectContaining({
        'Add-Padding': 'true',
      }),
      expect.objectContaining({
        timeoutMs: 1000,
        allowedHosts: ['api.pwnedpasswords.com'],
      })
    );
  });

  it('returns false when suffix is not in returned list', async () => {
    const mockResponseText = [
      '0018A45C4D1def:2',
      'AAAABBBBCCCCDDDDEEEEFFFF000011112222:5',
    ].join('\r\n');

    vi.spyOn(httpClient, 'get').mockResolvedValue({
      data: mockResponseText,
      status: 200,
      headers: {},
    } as any);

    const adapter = new HaveIBeenPwnedAdapter({
      baseUrl: 'https://api.pwnedpasswords.com/range',
      timeoutMs: 1000,
      userAgent: 'llm-observability-auth/1.0.0',
    });
    const isPwned = await adapter.checkIsPasswordPwned('unpwned_super_unique_password_2026');

    expect(isPwned).toBe(false);
  });

  it('fails open (returns false) when upstream returns HTTP 500', async () => {
    vi.spyOn(httpClient, 'get').mockResolvedValue({
      data: 'Internal Server Error',
      status: 500,
      headers: {},
    } as any);

    const adapter = new HaveIBeenPwnedAdapter({
      baseUrl: 'https://api.pwnedpasswords.com/range',
      timeoutMs: 1000,
      userAgent: 'llm-observability-auth/1.0.0',
    });
    const isPwned = await adapter.checkIsPasswordPwned('password');

    expect(isPwned).toBe(false);
  });

  it('fails open (returns false) when network times out or throws error', async () => {
    vi.spyOn(httpClient, 'get').mockRejectedValue(new Error('Network error or AbortError'));

    const adapter = new HaveIBeenPwnedAdapter({
      baseUrl: 'https://api.pwnedpasswords.com/range',
      timeoutMs: 50,
      userAgent: 'llm-observability-auth/1.0.0',
    });
    const isPwned = await adapter.checkIsPasswordPwned('password');

    expect(isPwned).toBe(false);
  });
});

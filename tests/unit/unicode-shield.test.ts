import { describe, it, expect } from 'vitest';
import {
  stripInvisibleAndBidiControls,
  normalizeUnicodeNFKC,
  detectCharacterScript,
  detectMixedScripts,
  toConfusableSkeleton,
  assertNoHomoglyphSpoof,
  UnicodeScript,
} from '../../src/shared/utils/unicode-shield.util';
import { normalizeString } from '../../src/shared/utils/string.util';
import {
  SignUpInputSchema,
  SignInInputSchema,
  CreateOrganizationInputSchema,
} from '../../src/features/auth/schema/auth.schema';

describe('Anti-Homoglyph & Unicode Normalization Shield (ADR 0032)', () => {
  describe('Zero-Width and Bidirectional Overrides Sanitization', () => {
    it('strips zero-width spaces and invisible characters', () => {
      const malicious = 'user\u200B\u200C\u200Dname@example.com';
      const cleaned = stripInvisibleAndBidiControls(malicious);
      expect(cleaned).toBe('username@example.com');
    });

    it('strips right-to-left override attacks', () => {
      const rloAttack = 'user\u202Ereversed@example.com';
      const cleaned = stripInvisibleAndBidiControls(rloAttack);
      expect(cleaned).toBe('userreversed@example.com');
    });

    it('handles non-string inputs safely without throwing', () => {
      expect(stripInvisibleAndBidiControls(null as unknown as string)).toBe('');
      expect(stripInvisibleAndBidiControls(undefined as unknown as string)).toBe('');
    });
  });

  describe('Canonical NFKC Normalization', () => {
    it('decomposes full-width latin characters into standard ASCII', () => {
      const fullWidth = 'ａｄｍｉｎ＠ｅｘａｍｐｌｅ．ｃｏｍ';
      const normalized = normalizeUnicodeNFKC(fullWidth);
      expect(normalized).toBe('admin@example.com');
    });

    it('normalizes ligature characters', () => {
      const ligature = 'ﬁrst@company.com';
      const normalized = normalizeUnicodeNFKC(ligature);
      expect(normalized).toBe('first@company.com');
    });

    it('integrates seamlessly with normalizeString', () => {
      const input = '  \u200B ＴＥＳＴ＿ＵＳＥＲ  ';
      const normalized = normalizeString(input, 'lower');
      expect(normalized).toBe('test_user');
    });
  });

  describe('Unicode Script Detection & Mixed-Script Analysis', () => {
    it('identifies Latin, Cyrillic, and Common scripts accurately', () => {
      expect(detectCharacterScript('a')).toBe(UnicodeScript.LATIN);
      expect(detectCharacterScript('\u0430')).toBe(UnicodeScript.CYRILLIC);
      expect(detectCharacterScript('\u03B1')).toBe(UnicodeScript.GREEK);
      expect(detectCharacterScript('@')).toBe(UnicodeScript.COMMON);
      expect(detectCharacterScript('.')).toBe(UnicodeScript.COMMON);
    });

    it('flags mixed Latin and Cyrillic script as mixed attack', () => {
      const mixed = 'аdmin@tenant.com';
      const result = detectMixedScripts(mixed);
      expect(result.isMixed).toBe(true);
      expect(result.scripts).toContain(UnicodeScript.CYRILLIC);
      expect(result.scripts).toContain(UnicodeScript.LATIN);
    });

    it('allows purely Latin identifiers', () => {
      const clean = 'developer_99@tenant.com';
      const result = detectMixedScripts(clean);
      expect(result.isMixed).toBe(false);
      expect(result.scripts).toEqual([UnicodeScript.LATIN]);
    });
  });

  describe('Confusable Skeleton Mapping & Impersonation Defense', () => {
    it('transforms Cyrillic homoglyph lookalikes into prototype Latin skeleton', () => {
      const cyrillicLookalikes = '\u0430\u0440\u0440\u043B\u0435';
      const skeleton = toConfusableSkeleton(cyrillicLookalikes);
      expect(skeleton).toBe('appлe');
    });

    it('rejects homoglyph spoofing targeting protected identities', () => {
      const maliciousCandidate = '\u0430dmin';
      expect(() => {
        assertNoHomoglyphSpoof(maliciousCandidate, ['admin', 'root', 'owner']);
      }).toThrow(/E_MIXED_SCRIPT_CONFUSABLE/);
    });

    it('blocks exact skeleton match when all-Cyrillic spoof matches protected Latin name', () => {
      const allCyrillicAdmin = '\u0430\u0440\u0440';
      const skeleton = toConfusableSkeleton(allCyrillicAdmin);
      expect(skeleton).toBe('app');

      expect(() => {
        assertNoHomoglyphSpoof(allCyrillicAdmin, ['app']);
      }).toThrow(/E_HOMOGLYPH_SPOOF_DETECTED/);
    });
  });

  describe('Zod Schema Integration & Input Rejection', () => {
    it('rejects sign-up with homoglyph spoofed admin email', () => {
      const payload = {
        email: 'аdmin@company.com',
        password: 'ValidPassword123!',
        name: 'Spoof Actor',
        organization_name: 'Acme Corp',
      };

      const result = SignUpInputSchema.safeParse(payload);
      expect(result.success).toBe(false);
      if (!result.success) {
        const errorMsg = result.error.errors.map((e) => e.message).join('; ');
        expect(errorMsg).toMatch(/E_MIXED_SCRIPT_CONFUSABLE/);
      }
    });

    it('successfully cleans and accepts valid email with whitespace and full-width dots', () => {
      const payload = {
        email: '  test.user@company.com  ',
        password: 'ValidPassword123!',
      };

      const result = SignInInputSchema.safeParse(payload);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.email).toBe('test.user@company.com');
      }
    });

    it('rejects mixed-script organization names', () => {
      const payload = {
        name: 'Аcme Corp',
      };

      const result = CreateOrganizationInputSchema.safeParse(payload);
      expect(result.success).toBe(false);
    });
  });
});

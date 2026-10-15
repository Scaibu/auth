/**
 * @file string.util.ts
 * @description Single unified string normalization utility adhering strictly to DRY.
 *
 * OVERALL ALGORITHM:
 * 1. Verify input type is a primitive string; return empty string for non-string inputs.
 * 2. Trim surrounding whitespace.
 * 3. Apply optional casing transformation ('lower' or 'upper') if specified, otherwise return trimmed string.
 */

import { normalizeUnicodeNFKC } from './unicode-shield.util';

export type StringCaseOption = 'lower' | 'upper' | 'none';

export function normalizeString(value: unknown, casing: StringCaseOption = 'none'): string {
  if (typeof value !== 'string') return '';
  const normalized = normalizeUnicodeNFKC(value).trim();
  if (casing === 'lower') return normalized.toLowerCase();
  if (casing === 'upper') return normalized.toUpperCase();
  return normalized;
}

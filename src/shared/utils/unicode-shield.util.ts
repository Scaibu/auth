export enum UnicodeScript {
  LATIN = 'LATIN',
  CYRILLIC = 'CYRILLIC',
  GREEK = 'GREEK',
  HEBREW = 'HEBREW',
  ARABIC = 'ARABIC',
  COMMON = 'COMMON',
  UNKNOWN = 'UNKNOWN',
}

const INVISIBLE_AND_BIDI_REGEX =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u206F\uFEFF]/g;

const CONFUSABLE_SKELETON_MAP: Record<string, string> = {
  '\u0430': 'a',
  '\u0410': 'A',
  '\u0435': 'e',
  '\u0415': 'E',
  '\u043E': 'o',
  '\u041E': 'O',
  '\u0440': 'p',
  '\u0420': 'P',
  '\u0441': 'c',
  '\u0421': 'C',
  '\u0443': 'y',
  '\u0423': 'Y',
  '\u0445': 'x',
  '\u0425': 'X',
  '\u0456': 'i',
  '\u0406': 'I',
  '\u0458': 'j',
  '\u0408': 'J',
  '\u0455': 's',
  '\u0405': 'S',
  '\u0432': 'b',
  '\u0412': 'B',
  '\u043D': 'h',
  '\u041D': 'H',
  '\u043C': 'm',
  '\u041C': 'M',
  '\u0442': 't',
  '\u0422': 'T',
  '\u043A': 'k',
  '\u042A': 'K',
  '\u03B1': 'a',
  '\u0391': 'A',
  '\u03BF': 'o',
  '\u039F': 'O',
  '\u03B5': 'e',
  '\u0395': 'E',
  '\u03C1': 'p',
  '\u03A1': 'P',
  '\u03C4': 't',
  '\u03A4': 'T',
  '\u03B9': 'i',
  '\u0399': 'I',
  '\u03BA': 'k',
  '\u039A': 'K',
  '\u03BD': 'v',
  '\u039D': 'N',
  '\u03C5': 'u',
  '\u03A5': 'Y',
  '\u03C7': 'x',
  '\u03A7': 'X',
  '\u2010': '-',
  '\u2011': '-',
  '\u2012': '-',
  '\u2013': '-',
  '\u2014': '-',
  '\u2015': '-',
  '\u2212': '-',
  '\uFF0D': '-',
  '\uFF20': '@',
  '\uFF0E': '.',
  '\u3002': '.',
  '\uFF0F': '/',
};

export function stripInvisibleAndBidiControls(input: string): string {
  if (typeof input !== 'string') return '';
  return input.replace(INVISIBLE_AND_BIDI_REGEX, '');
}

export function normalizeUnicodeNFKC(input: string): string {
  if (typeof input !== 'string') return '';
  const sanitized = stripInvisibleAndBidiControls(input);
  return sanitized.normalize('NFKC');
}

export function detectCharacterScript(char: string): UnicodeScript {
  const code = char.codePointAt(0);
  if (code === undefined) return UnicodeScript.UNKNOWN;

  if (
    (code >= 0x0020 && code <= 0x0040) ||
    (code >= 0x005b && code <= 0x0060) ||
    (code >= 0x007b && code <= 0x007e) ||
    code === 0x002e ||
    code === 0x0040 ||
    code === 0x005f ||
    code === 0x002d
  ) {
    return UnicodeScript.COMMON;
  }

  if (
    (code >= 0x0041 && code <= 0x005a) ||
    (code >= 0x0061 && code <= 0x007a) ||
    (code >= 0x00c0 && code <= 0x024f) ||
    (code >= 0x1e00 && code <= 0x1eff)
  ) {
    return UnicodeScript.LATIN;
  }

  if ((code >= 0x0400 && code <= 0x04ff) || (code >= 0x0500 && code <= 0x052f)) {
    return UnicodeScript.CYRILLIC;
  }

  if (code >= 0x0370 && code <= 0x03ff) {
    return UnicodeScript.GREEK;
  }

  if (code >= 0x0590 && code <= 0x05ff) {
    return UnicodeScript.HEBREW;
  }

  if (code >= 0x0600 && code <= 0x06ff) {
    return UnicodeScript.ARABIC;
  }

  return UnicodeScript.UNKNOWN;
}

export function detectMixedScripts(input: string): {
  isMixed: boolean;
  scripts: UnicodeScript[];
} {
  const scriptSet = new Set<UnicodeScript>();

  for (const char of input) {
    const script = detectCharacterScript(char);
    if (script !== UnicodeScript.COMMON && script !== UnicodeScript.UNKNOWN) {
      scriptSet.add(script);
    }
  }

  const scripts = Array.from(scriptSet);
  const isMixed =
    scripts.length > 1 &&
    (scripts.includes(UnicodeScript.LATIN) &&
      (scripts.includes(UnicodeScript.CYRILLIC) || scripts.includes(UnicodeScript.GREEK)));

  return { isMixed, scripts };
}

export function toConfusableSkeleton(input: string): string {
  if (typeof input !== 'string') return '';
  const normalized = normalizeUnicodeNFKC(input);

  let skeleton = '';
  for (const char of normalized) {
    if (CONFUSABLE_SKELETON_MAP[char]) {
      skeleton += CONFUSABLE_SKELETON_MAP[char];
    } else {
      skeleton += char;
    }
  }

  return skeleton.toLowerCase();
}

export function assertNoHomoglyphSpoof(
  candidate: string,
  protectedTargets: string[]
): void {
  const candidateSkeleton = toConfusableSkeleton(candidate);
  const mixedCheck = detectMixedScripts(candidate);

  if (mixedCheck.isMixed) {
    throw new Error('E_MIXED_SCRIPT_CONFUSABLE: Mixed-script identifier prohibited for security');
  }

  for (const target of protectedTargets) {
    const targetSkeleton = toConfusableSkeleton(target);
    if (candidateSkeleton === targetSkeleton && candidate.toLowerCase() !== target.toLowerCase()) {
      throw new Error(`E_HOMOGLYPH_SPOOF_DETECTED: Candidate "${candidate}" spoofs protected identity "${target}"`);
    }
  }
}

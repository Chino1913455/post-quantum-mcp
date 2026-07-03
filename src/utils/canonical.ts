/** Shared encoding + deterministic-JSON helpers for signed payloads. */

export const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');
export const ub = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));
export const utf8 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'utf8'));

/** Format-aware encode/decode (base64 default, hex on request). */
export const encFmt = (u: Uint8Array, fmt?: string): string => Buffer.from(u).toString(fmt === 'hex' ? 'hex' : 'base64');
export const decFmt = (s: string, fmt?: string): Uint8Array => new Uint8Array(Buffer.from(s, fmt === 'hex' ? 'hex' : 'base64'));

/**
 * Deterministic JSON serialization (recursively sorted object keys) so that a
 * signed payload reproduces byte-for-byte at verification time regardless of
 * property order. Required for any sign-then-verify-over-JSON flow.
 */
export function stableStringify(v: any): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  return (
    '{' +
    Object.keys(v)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + stableStringify((v as any)[k]))
      .join(',') +
    '}'
  );
}

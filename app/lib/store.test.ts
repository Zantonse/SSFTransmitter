import { describe, expect, it } from 'vitest';
import { getKeyStore, isValidTenantId } from './store';

describe('key store (in-memory fallback)', () => {
  it('isolates tenants', async () => {
    const store = getKeyStore();
    await store.putKey('tenant-aaaaaa', { kty: 'RSA', kid: 'a1' });
    await store.putKey('tenant-bbbbbb', { kty: 'RSA', kid: 'b1' });
    expect((await store.getKeys('tenant-aaaaaa')).map((k) => k.kid)).toEqual(['a1']);
    expect((await store.getKeys('tenant-bbbbbb')).map((k) => k.kid)).toEqual(['b1']);
  });

  it('keeps the current and previous key, newest first', async () => {
    const store = getKeyStore();
    await store.putKey('tenant-rotate', { kty: 'RSA', kid: 'k1' });
    await store.putKey('tenant-rotate', { kty: 'RSA', kid: 'k2' });
    await store.putKey('tenant-rotate', { kty: 'RSA', kid: 'k3' });
    expect((await store.getKeys('tenant-rotate')).map((k) => k.kid)).toEqual(['k3', 'k2']);
  });

  it('validates tenant IDs', () => {
    expect(isValidTenantId('abc123def456')).toBe(true);
    expect(isValidTenantId('short')).toBe(false);
    expect(isValidTenantId('../etc/passwd')).toBe(false);
  });
});

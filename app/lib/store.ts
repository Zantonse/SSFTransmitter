import { Redis } from '@upstash/redis';
import type { JWK } from 'jose';

// Key/value store for published JWKS keys.
// Uses Upstash Redis when UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are set
// (Vercel Marketplace integration), so keys survive cold starts and are shared
// across serverless instances. Falls back to an in-memory Map for local dev.

const KEY_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const MAX_KEYS_PER_TENANT = 2; // current + previous, so in-flight SETs still verify after a rotation

export const LEGACY_TENANT = '_legacy';

const TENANT_ID_PATTERN = /^[a-zA-Z0-9_-]{6,64}$/;

export function isValidTenantId(tenantId: string): boolean {
  return TENANT_ID_PATTERN.test(tenantId);
}

interface KeyStore {
  getKeys(tenantId: string): Promise<JWK[]>;
  putKey(tenantId: string, jwk: JWK): Promise<void>;
}

class MemoryKeyStore implements KeyStore {
  private tenants = new Map<string, JWK[]>();

  async getKeys(tenantId: string) {
    return this.tenants.get(tenantId) ?? [];
  }

  async putKey(tenantId: string, jwk: JWK) {
    const existing = (this.tenants.get(tenantId) ?? []).filter((k) => k.kid !== jwk.kid);
    this.tenants.set(tenantId, [jwk, ...existing].slice(0, MAX_KEYS_PER_TENANT));
  }
}

class RedisKeyStore implements KeyStore {
  constructor(private redis: Redis) {}

  private key(tenantId: string) {
    return `ssf:jwks:${tenantId}`;
  }

  async getKeys(tenantId: string) {
    return (await this.redis.get<JWK[]>(this.key(tenantId))) ?? [];
  }

  async putKey(tenantId: string, jwk: JWK) {
    const existing = (await this.getKeys(tenantId)).filter((k) => k.kid !== jwk.kid);
    await this.redis.set(this.key(tenantId), [jwk, ...existing].slice(0, MAX_KEYS_PER_TENANT), {
      ex: KEY_TTL_SECONDS,
    });
  }
}

// Keep the in-memory store on globalThis so Next.js dev-mode module reloads don't wipe it.
const globalStore = globalThis as unknown as { __ssfKeyStore?: KeyStore };

export function getKeyStore(): KeyStore {
  if (!globalStore.__ssfKeyStore) {
    const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
    const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;
    globalStore.__ssfKeyStore = url && token ? new RedisKeyStore(new Redis({ url, token })) : new MemoryKeyStore();
  }
  return globalStore.__ssfKeyStore;
}

export function isPersistentStore(): boolean {
  return getKeyStore() instanceof RedisKeyStore;
}

import type { NextRequest } from 'next/server';

export const JWKS_HEADERS = {
  'Content-Type': 'application/json',
  'Cache-Control': 'no-cache',
  'Access-Control-Allow-Origin': '*',
};

export function getAppUrl(request: NextRequest): string {
  const proto = request.headers.get('x-forwarded-proto') ?? 'https';
  const host = request.headers.get('host') ?? 'localhost:3000';
  return `${proto}://${host}`;
}

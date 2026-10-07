import { NextRequest, NextResponse } from 'next/server';
import { getKeyStore, isValidTenantId } from '../../../lib/store';
import { JWKS_HEADERS } from '../../../lib/http';

// Per-tenant JWKS. Each browser gets its own tenant ID, so SEs sharing a deployment
// never overwrite each other's keys.
export async function GET(_request: NextRequest, { params }: { params: Promise<{ tenant: string }> }) {
  const { tenant } = await params;
  if (!isValidTenantId(tenant)) {
    return NextResponse.json({ error: 'Invalid tenant ID' }, { status: 400 });
  }
  const keys = await getKeyStore().getKeys(tenant);
  return NextResponse.json({ keys }, { headers: JWKS_HEADERS });
}

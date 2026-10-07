import { type JWK } from 'jose';
import { NextRequest, NextResponse } from 'next/server';
import { getKeyStore, isValidTenantId, LEGACY_TENANT } from '../../lib/store';
import { JWKS_HEADERS } from '../../lib/http';

// Legacy single-tenant JWKS (issuer = app origin). New setups use /api/jwks/{tenant}.
export async function GET() {
  const keys = await getKeyStore().getKeys(LEGACY_TENANT);
  return NextResponse.json({ keys }, { headers: JWKS_HEADERS });
}

export async function POST(request: NextRequest) {
  let body: unknown;

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: 'Invalid JSON in request body' },
      { status: 400 }
    );
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    !('kid' in body) ||
    !('publicJwk' in body)
  ) {
    return NextResponse.json(
      { error: 'Missing required fields: kid, publicJwk' },
      { status: 400 }
    );
  }

  const { kid, publicJwk, tenantId } = body as { kid: unknown; publicJwk: unknown; tenantId?: unknown };

  if (typeof kid !== 'string' || !kid) {
    return NextResponse.json(
      { error: 'Field "kid" must be a non-empty string' },
      { status: 400 }
    );
  }

  if (typeof publicJwk !== 'object' || publicJwk === null) {
    return NextResponse.json(
      { error: 'Field "publicJwk" must be a JWK object' },
      { status: 400 }
    );
  }

  if ('d' in publicJwk) {
    return NextResponse.json(
      { error: 'Refusing to publish a private key — send the public JWK only' },
      { status: 400 }
    );
  }

  if (tenantId !== undefined && (typeof tenantId !== 'string' || !isValidTenantId(tenantId))) {
    return NextResponse.json(
      { error: 'Field "tenantId" must be 6-64 characters of [a-zA-Z0-9_-]' },
      { status: 400 }
    );
  }

  const tenant = typeof tenantId === 'string' ? tenantId : LEGACY_TENANT;
  await getKeyStore().putKey(tenant, { ...(publicJwk as JWK), kid });

  return NextResponse.json({ success: true, kid, tenantId: tenant });
}

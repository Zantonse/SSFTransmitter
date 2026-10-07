import { NextRequest, NextResponse } from 'next/server';
import { isValidTenantId } from '../../../../lib/store';
import { getAppUrl } from '../../../../lib/http';

// Per-tenant SSF discovery document. Issuer is {appUrl}/t/{tenant}; register this
// URL in Okta as the provider's well-known URL.
export async function GET(request: NextRequest, { params }: { params: Promise<{ tenant: string }> }) {
  const { tenant } = await params;
  if (!isValidTenantId(tenant)) {
    return NextResponse.json({ error: 'Invalid tenant ID' }, { status: 400 });
  }
  const appUrl = getAppUrl(request);

  return NextResponse.json(
    {
      issuer: `${appUrl}/t/${tenant}`,
      jwks_uri: `${appUrl}/api/jwks/${tenant}`,
    },
    {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      },
    }
  );
}

import { NextRequest, NextResponse } from 'next/server';
import { getAppUrl } from '../../lib/http';

// Legacy single-tenant discovery document (issuer = app origin).
// New setups use /t/{tenant}/.well-known/ssf-configuration.
export async function GET(request: NextRequest) {
  const appUrl = getAppUrl(request);

  return NextResponse.json(
    {
      issuer: appUrl,
      jwks_uri: `${appUrl}/api/jwks`,
    },
    {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      },
    }
  );
}

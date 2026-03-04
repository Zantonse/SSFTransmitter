import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const proto = request.headers.get('x-forwarded-proto') ?? 'https';
  const host = request.headers.get('host') ?? 'localhost:3000';
  const appUrl = `${proto}://${host}`;

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

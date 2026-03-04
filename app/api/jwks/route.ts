import { type JWK } from 'jose';
import { NextRequest, NextResponse } from 'next/server';

const keyStore = new Map<string, JWK>();

export async function GET() {
  const keys = Array.from(keyStore.values());

  return NextResponse.json(
    { keys },
    {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
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

  const { kid, publicJwk } = body as { kid: unknown; publicJwk: unknown };

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

  keyStore.clear();
  keyStore.set(kid, publicJwk as JWK);

  return NextResponse.json({ success: true, kid });
}

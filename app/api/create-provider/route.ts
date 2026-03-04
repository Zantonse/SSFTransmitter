import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  let body: {
    oktaDomain?: string;
    apiToken?: string;
    appUrl?: string;
    providerName?: string;
  };

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { success: false, error: 'invalid_request', errorDescription: 'Request body must be valid JSON', status: 400 },
      { status: 400 }
    );
  }

  const { oktaDomain, apiToken, appUrl, providerName } = body;

  if (!oktaDomain || !apiToken || !appUrl) {
    return NextResponse.json(
      { success: false, error: 'missing_required_fields', errorDescription: 'oktaDomain, apiToken, and appUrl are required', status: 400 },
      { status: 400 }
    );
  }

  let oktaHost: string;
  try {
    const domainWithProtocol = oktaDomain.startsWith('http://') || oktaDomain.startsWith('https://')
      ? oktaDomain
      : `https://${oktaDomain}`;
    oktaHost = new URL(domainWithProtocol).hostname;
  } catch {
    return NextResponse.json(
      { success: false, error: 'invalid_domain', errorDescription: 'The provided oktaDomain is not a valid URL', status: 400 },
      { status: 400 }
    );
  }

  const oktaEndpoint = `https://${oktaHost}/api/v1/security-events-providers`;
  const well_known_url = `${appUrl.replace(/\/$/, '')}/.well-known/ssf-configuration`;

  const requestBody = {
    name: providerName || 'SSF Transmitter',
    type: 'SSF Transmitter',
    settings: {
      well_known_url,
    },
  };

  try {
    const response = await fetch(oktaEndpoint, {
      method: 'POST',
      headers: {
        Authorization: `SSWS ${apiToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    let data: Record<string, unknown>;
    try {
      data = await response.json();
    } catch {
      return NextResponse.json(
        { success: false, error: 'invalid_response', errorDescription: 'Okta returned a non-JSON response', status: response.status },
        { status: response.status }
      );
    }

    if (!response.ok) {
      const error = (data.error as string) || (data.errorCode as string) || 'okta_error';
      const errorDescription =
        (data.errorDescription as string) ||
        (data.errorSummary as string) ||
        `Okta returned status ${response.status}`;

      return NextResponse.json(
        { success: false, error, errorDescription, status: response.status },
        { status: response.status }
      );
    }

    return NextResponse.json({
      success: true,
      providerId: data.id,
      providerName: data.name,
      providerStatus: data.status,
      settings: data.settings,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Network request failed';
    return NextResponse.json(
      { success: false, error: 'network_error', errorDescription: message, status: 500 },
      { status: 500 }
    );
  }
}

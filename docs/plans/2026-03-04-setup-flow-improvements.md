# Setup Flow Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce SSF Transmitter setup from ~10 manual steps to 4 in-app steps by adding auto-hosted JWKS, auto-register provider via Okta API, and a guided stepper UI.

**Architecture:** Three new API routes (`/api/jwks`, `/.well-known/ssf-configuration/route.ts`, `/api/create-provider`) replace the manual npoint.io JWKS hosting and Okta Admin Console provider creation. A `SetupStepper` component tracks completion state. All new state (API token, provider registration) persists to the existing `ssf-transmitter-config` localStorage key.

**Tech Stack:** Next.js 16 API routes, jose (already installed), React with React Compiler, existing CSS custom properties system.

---

### Task 1: JWKS API Route (GET + POST)

**Files:**
- Create: `app/api/jwks/route.ts`

**Step 1: Create the JWKS route with in-memory store**

```typescript
// app/api/jwks/route.ts
import { NextRequest, NextResponse } from 'next/server';
import type { JWK } from 'jose';

// In-memory JWKS store — keys are ephemeral (regenerated each session)
const jwksStore: Map<string, JWK> = new Map();

export async function GET() {
  const keys = Array.from(jwksStore.values());
  return NextResponse.json(
    { keys },
    {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { kid, publicJwk } = body;

    if (!kid || !publicJwk) {
      return NextResponse.json(
        { error: "Missing 'kid' or 'publicJwk' in request body" },
        { status: 400 }
      );
    }

    // Clear previous keys and store the new one
    jwksStore.clear();
    jwksStore.set(kid, publicJwk);

    return NextResponse.json({ success: true, kid });
  } catch {
    return NextResponse.json(
      { error: 'Invalid request body' },
      { status: 400 }
    );
  }
}
```

**Step 2: Verify the route works**

Run: `npm run dev`
Test: `curl http://localhost:3000/api/jwks` — should return `{"keys":[]}`

**Step 3: Commit**

```bash
git add app/api/jwks/route.ts
git commit -m "feat: add JWKS API route with in-memory key store"
```

---

### Task 2: SSF Well-Known Configuration Route

**Files:**
- Create: `app/.well-known/ssf-configuration/route.ts`

**Step 1: Create the well-known route**

```typescript
// app/.well-known/ssf-configuration/route.ts
import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  // Derive the app URL from the request headers
  const host = req.headers.get('host') || 'localhost:3000';
  const protocol = req.headers.get('x-forwarded-proto') || 'https';
  const appUrl = `${protocol}://${host}`;

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
```

**Step 2: Verify the route works**

Run: `curl http://localhost:3000/.well-known/ssf-configuration`
Expected: `{"issuer":"http://localhost:3000","jwks_uri":"http://localhost:3000/api/jwks"}`

**Step 3: Commit**

```bash
git add "app/.well-known/ssf-configuration/route.ts"
git commit -m "feat: add SSF well-known configuration endpoint"
```

---

### Task 3: Create Provider API Route

**Files:**
- Create: `app/api/create-provider/route.ts`

**Step 1: Create the Okta provider registration proxy**

This route proxies the call to `POST /api/v1/security-events-providers` on the user's Okta domain, using the SSWS API token for auth.

```typescript
// app/api/create-provider/route.ts
import { NextRequest, NextResponse } from 'next/server';

interface CreateProviderRequest {
  oktaDomain: string;
  apiToken: string;
  appUrl: string;
  providerName?: string;
}

export async function POST(req: NextRequest) {
  try {
    const body: CreateProviderRequest = await req.json();
    const { oktaDomain, apiToken, appUrl, providerName } = body;

    if (!oktaDomain || !apiToken || !appUrl) {
      return NextResponse.json(
        { error: 'Missing oktaDomain, apiToken, or appUrl' },
        { status: 400 }
      );
    }

    // Sanitize domain
    let domain = oktaDomain.trim();
    if (!domain.startsWith('http')) {
      domain = `https://${domain}`;
    }

    let oktaHost;
    try {
      oktaHost = new URL(domain).hostname;
    } catch {
      return NextResponse.json(
        { error: `Invalid Okta domain: ${oktaDomain}` },
        { status: 400 }
      );
    }

    const endpoint = `https://${oktaHost}/api/v1/security-events-providers`;
    const wellKnownUrl = `${appUrl.replace(/\/+$/, '')}/.well-known/ssf-configuration`;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `SSWS ${apiToken}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        name: providerName || 'SSF Transmitter',
        type: 'SSF Transmitter',
        settings: {
          well_known_url: wellKnownUrl,
        },
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(
        {
          success: false,
          error: data.errorCode || data.error || `HTTP ${response.status}`,
          errorDescription: data.errorSummary || data.error_description || JSON.stringify(data),
          status: response.status,
        },
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
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}
```

**Step 2: Commit**

```bash
git add app/api/create-provider/route.ts
git commit -m "feat: add Okta SSF provider registration API route"
```

---

### Task 4: SetupStepper Component

**Files:**
- Create: `app/components/SetupStepper.tsx`

**Step 1: Create the stepper component**

Props interface: receives four boolean completion flags. Renders a horizontal bar of 4 numbered steps with connecting lines. Clicking a step calls `onStepClick(stepId)`.

```typescript
// app/components/SetupStepper.tsx
'use client';

interface SetupStep {
  id: string;
  label: string;
  optional?: boolean;
}

const STEPS: SetupStep[] = [
  { id: 'configure', label: 'Configure' },
  { id: 'keys', label: 'Generate Keys' },
  { id: 'register', label: 'Register Provider', optional: true },
  { id: 'send', label: 'Send Events' },
];

interface SetupStepperProps {
  completedSteps: Record<string, boolean>;
  onStepClick: (stepId: string) => void;
}

export default function SetupStepper({ completedSteps, onStepClick }: SetupStepperProps) {
  // Find first incomplete step
  const currentStepIndex = STEPS.findIndex((s) => !completedSteps[s.id]);

  return (
    <div className="setup-stepper">
      {STEPS.map((step, i) => {
        const isComplete = completedSteps[step.id];
        const isCurrent = i === currentStepIndex;

        return (
          <div key={step.id} className="setup-stepper-item">
            {i > 0 && (
              <div className={`setup-stepper-line ${completedSteps[STEPS[i - 1].id] ? 'complete' : ''}`} />
            )}
            <button
              className={`setup-stepper-circle ${isComplete ? 'complete' : ''} ${isCurrent ? 'current' : ''}`}
              onClick={() => onStepClick(step.id)}
              title={step.label}
            >
              {isComplete ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              ) : (
                <span>{i + 1}</span>
              )}
            </button>
            <span className={`setup-stepper-label ${isComplete ? 'complete' : ''} ${isCurrent ? 'current' : ''}`}>
              {step.label}
              {step.optional && <span className="setup-stepper-optional">(optional)</span>}
            </span>
          </div>
        );
      })}
    </div>
  );
}
```

**Step 2: Commit**

```bash
git add app/components/SetupStepper.tsx
git commit -m "feat: add SetupStepper progress indicator component"
```

---

### Task 5: Add Stepper CSS

**Files:**
- Modify: `app/globals.css` (append at end)

**Step 1: Add stepper styles**

Append to end of `app/globals.css`:

```css
/* Setup Stepper */
.setup-stepper {
  display: flex;
  align-items: center;
  padding: 16px 24px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-default);
  border-radius: 10px;
  margin-bottom: 24px;
  gap: 0;
}

.setup-stepper-item {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
  min-width: 0;
}

.setup-stepper-item:first-child {
  flex: 0 0 auto;
}

.setup-stepper-line {
  flex: 1;
  height: 2px;
  background: var(--border-default);
  margin: 0 4px;
  transition: background 0.3s ease;
}

.setup-stepper-line.complete {
  background: var(--accent-green);
}

.setup-stepper-circle {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--bg-tertiary);
  border: 2px solid var(--border-default);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  font-weight: 700;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.3s ease;
  flex-shrink: 0;
}

.setup-stepper-circle:hover {
  border-color: var(--accent-blue);
  color: var(--accent-blue);
}

.setup-stepper-circle.complete {
  background: var(--accent-green);
  border-color: var(--accent-green);
  color: white;
}

.setup-stepper-circle.current {
  border-color: var(--accent-blue);
  color: var(--accent-blue);
  box-shadow: 0 0 0 4px rgba(22, 98, 221, 0.15);
  animation: stepper-pulse 2s infinite;
}

@keyframes stepper-pulse {
  0%, 100% {
    box-shadow: 0 0 0 4px rgba(22, 98, 221, 0.15);
  }
  50% {
    box-shadow: 0 0 0 8px rgba(22, 98, 221, 0.08);
  }
}

.setup-stepper-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  white-space: nowrap;
  transition: color 0.3s ease;
}

.setup-stepper-label.complete {
  color: var(--accent-green);
}

.setup-stepper-label.current {
  color: var(--text-primary);
}

.setup-stepper-optional {
  display: block;
  font-size: 10px;
  font-weight: 400;
  color: var(--text-muted);
  opacity: 0.7;
}

/* Provider Registration Section */
.provider-registration-status {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  background: linear-gradient(135deg, rgba(63, 185, 80, 0.1), rgba(63, 185, 80, 0.03));
  border: 1px solid rgba(63, 185, 80, 0.3);
  border-radius: 8px;
}

.provider-status-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 3px 8px;
  border-radius: 4px;
}

.provider-status-badge.active {
  background: var(--accent-green);
  color: white;
}

/* API Key Input */
.api-key-wrapper {
  position: relative;
  display: flex;
  gap: 0;
}

.api-key-wrapper .input-field {
  padding-right: 44px;
}

.api-key-toggle {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  width: 32px;
  height: 32px;
  border-radius: 6px;
  background: transparent;
  border: none;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-muted);
  cursor: pointer;
  transition: color 0.2s ease;
}

.api-key-toggle:hover {
  color: var(--text-secondary);
}

/* Alert success variant */
.alert-success {
  background: linear-gradient(135deg, rgba(63, 185, 80, 0.15), rgba(63, 185, 80, 0.05));
  border: 1px solid rgba(63, 185, 80, 0.3);
  border-radius: 8px;
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.alert-success .alert-icon {
  color: var(--accent-green);
  font-size: 18px;
}

.alert-success .alert-text {
  color: var(--accent-green);
  font-size: 13px;
}
```

**Step 2: Commit**

```bash
git add app/globals.css
git commit -m "feat: add stepper and provider registration CSS styles"
```

---

### Task 6: Integrate Everything into page.tsx

This is the largest task. It modifies `app/page.tsx` to:
1. Add new state: `oktaApiToken`, `showApiToken`, `providerRegistration`, `jwksHosted`
2. Auto-push keys to `/api/jwks` after generation
3. Auto-detect app URL for issuer
4. Replace npoint.io JWKS flow with hosted JWKS status
5. Add Okta API Key input to Configuration card
6. Add Provider Registration card (new Section 03)
7. Renumber Transmission to Section 04
8. Add `SetupStepper` above the grid
9. Persist new state to localStorage

**Files:**
- Modify: `app/page.tsx`

**Step 1: Add new imports and state**

At the top, add the `SetupStepper` import. Add new state variables after the existing ones.

New state:
```typescript
const [oktaApiToken, setOktaApiToken] = useState('');
const [showApiToken, setShowApiToken] = useState(false);
const [providerRegistration, setProviderRegistration] = useState<{
  status: 'idle' | 'loading' | 'success' | 'error';
  providerId?: string;
  providerStatus?: string;
  error?: string;
}>({ status: 'idle' });
const [jwksHosted, setJwksHosted] = useState(false);
```

**Step 2: Modify key generation to auto-push JWKS**

Replace `handleGenerateKeys` to push the public key to `/api/jwks` after generation:

```typescript
const handleGenerateKeys = async () => {
  addLog('Generating RSA-256 key pair...', 'info');
  const result = await generateKeyPair();
  setKeys(result);
  addLog(`Key pair generated. KID: ${result.kid}`, 'success');

  // Auto-push public key to hosted JWKS endpoint
  try {
    const res = await fetch('/api/jwks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kid: result.kid, publicJwk: result.publicJwk }),
    });
    if (res.ok) {
      setJwksHosted(true);
      addLog('Public key published to /api/jwks', 'success');
    }
  } catch {
    addLog('Warning: Could not publish key to /api/jwks', 'error');
  }
};
```

**Step 3: Add provider registration handler**

```typescript
const handleCreateProvider = async () => {
  if (!config.oktaDomain || !oktaApiToken) return;
  setProviderRegistration({ status: 'loading' });
  addLog('Registering SSF provider in Okta...', 'info');

  try {
    const appUrl = window.location.origin;
    const res = await fetch('/api/create-provider', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        oktaDomain: config.oktaDomain,
        apiToken: oktaApiToken,
        appUrl,
      }),
    });
    const data = await res.json();
    if (data.success) {
      setProviderRegistration({
        status: 'success',
        providerId: data.providerId,
        providerStatus: data.providerStatus,
      });
      addLog(`Provider registered: ${data.providerId} (${data.providerStatus})`, 'success');
      // Auto-set issuer URL to app URL
      setConfig((prev) => ({ ...prev, issuerUrl: appUrl }));
    } else {
      setProviderRegistration({
        status: 'error',
        error: data.errorDescription || data.error,
      });
      addLog(`Provider registration failed: ${data.error}`, 'error');
    }
  } catch {
    setProviderRegistration({ status: 'error', error: 'Network error' });
    addLog('Provider registration failed: network error', 'error');
  }
};
```

**Step 4: Add stepper scroll handler**

```typescript
const handleStepClick = (stepId: string) => {
  const sectionMap: Record<string, string> = {
    configure: 'section-config',
    keys: 'section-keys',
    register: 'section-register',
    send: 'section-transmit',
  };
  const el = document.getElementById(sectionMap[stepId]);
  el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
};
```

**Step 5: Update localStorage load/save**

In the mount effect (loading from localStorage), add:
```typescript
if (parsed.oktaApiToken) setOktaApiToken(parsed.oktaApiToken);
if (parsed.providerRegistration) setProviderRegistration(parsed.providerRegistration);
```

In the save effect, add `oktaApiToken` and `providerRegistration` to the persisted object.

**Step 6: Re-push keys on page load if keys exist in state**

Add a `useEffect` that re-pushes keys to `/api/jwks` when the component hydrates with existing keys:

```typescript
useEffect(() => {
  if (!keys) return;
  fetch('/api/jwks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kid: keys.kid, publicJwk: keys.publicJwk }),
  }).then((res) => {
    if (res.ok) setJwksHosted(true);
  }).catch(() => {});
}, [keys]);
```

Note: keys are generated fresh each session (not persisted), so this effect only runs if the user generates keys in the current session. It serves as a safety net if the server restarts mid-session.

**Step 7: Update the JSX**

Key changes to the JSX:
1. Add `<SetupStepper>` after `<SessionStats>` and before the grid
2. Add `id="section-config"` to the Configuration card, `id="section-keys"` to Key Management, etc.
3. Add **Okta API Key** field to Section 01 (Configuration card) — password input with show/hide toggle, placed after the Target Subject field
4. In Section 02 (Key Management), replace the entire npoint.io hosting flow (`.jwks-hosting-flow` div, lines ~888-934) with a simple status indicator showing the JWKS is hosted at the app URL
5. Add new **Section 03 - Register Provider** card with:
   - Provider name display
   - Well-known URL display
   - "Create Provider in Okta" button (disabled until domain + API token + keys)
   - Success/error state display
6. Renumber Transmission to Section 04, Last Payload to 05

The `completedSteps` prop for the stepper:
```typescript
const completedSteps = {
  configure: Boolean(config.oktaDomain && config.subjectEmail),
  keys: Boolean(keys && jwksHosted),
  register: providerRegistration.status === 'success',
  send: history.length > 0,
};
```

**Step 8: Commit**

```bash
git add app/page.tsx
git commit -m "feat: integrate auto-JWKS, provider registration, and stepper into main page"
```

---

### Task 7: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Update the architecture docs**

Update the API Routes section to document the three new routes. Update the Key Generation Flow to reflect auto-hosting. Add a note about the provider registration flow.

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with new API routes and setup flow"
```

---

### Task 8: Manual Verification

**Step 1: Run dev server and test full flow**

```bash
npm run dev
```

1. Open `http://localhost:3000`
2. Verify stepper appears with 4 steps, step 1 highlighted
3. Enter Okta domain and email — step 1 should complete (green check)
4. Click Generate Keys — step 2 should complete
5. Verify `curl http://localhost:3000/api/jwks` returns the public key
6. Verify `curl http://localhost:3000/.well-known/ssf-configuration` returns correct JSON
7. (Optional) Enter API token and create provider — step 3 completes
8. Send an event — step 4 completes

**Step 2: Run production build**

```bash
npm run build
```

Verify no TypeScript or build errors.

**Step 3: Final commit and push**

```bash
git push origin feature/improvements
```

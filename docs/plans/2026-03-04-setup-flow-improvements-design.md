# Setup Flow Improvements Design

**Date**: 2026-03-04
**Status**: Approved

## Goal

Reduce SSF Transmitter setup from ~10 manual steps (including leaving the app twice) to 4 in-app steps. Three features: auto-hosted JWKS, auto-register SSF provider in Okta, and a guided stepper UI.

## Feature 1: Auto-Hosted JWKS Endpoint

### Problem

Users must copy JWKS JSON, visit npoint.io, paste it, get a URL, paste it back, and verify. Six steps, two outside the app.

### Design

Two new GET routes serve the JWKS and SSF well-known config directly from this app:

- **`GET /api/jwks`** — Returns `{ keys: [...] }` with `Content-Type: application/json`. Public key JWK stored server-side in an in-memory Map keyed by `kid`.
- **`POST /api/jwks`** — Accepts `{ kid, publicJwk }` from the client after key generation. Stores the key in the server-side Map.
- **`GET /.well-known/ssf-configuration`** — Returns `{ issuer: "<app-url>", jwks_uri: "<app-url>/api/jwks" }`.

### Client Changes

- After `generateKeyPair()`, the client POSTs the public JWK to `/api/jwks`.
- The issuer URL auto-populates to the app's own origin (detected via `window.location.origin`).
- The Key Management card (Section 02) replaces the npoint.io flow with a status line: "JWKS hosted at `<origin>/api/jwks`" with a verify checkmark.
- The existing npoint.io instructions, URL input, and Verify button are removed.

### Trade-offs

In-memory storage means keys are lost on redeploy. Acceptable because keys are already ephemeral (generated fresh each browser session). The client re-pushes the key on page load if keys exist in state.

## Feature 2: Auto-Register SSF Provider in Okta

### Okta API

`POST https://{oktaDomain}/api/v1/security-events-providers` with `Authorization: SSWS {apiToken}`.

Two modes: well-known URL or issuer+JWKS. We use well-known URL mode:

```json
{
  "name": "SSF Transmitter",
  "type": "SSF Transmitter",
  "settings": {
    "well_known_url": "https://<app-url>/.well-known/ssf-configuration"
  }
}
```

Returns `{ id, name, status: "ACTIVE", settings: { ... } }` on success.

### New API Route

**`POST /api/create-provider`** — Server-side proxy to avoid CORS. Accepts `{ oktaDomain, apiToken, appUrl }`. Constructs the Okta API call. Returns the Okta response (provider ID, status, or error details).

### Client Changes

- New `oktaApiToken` field in the config state, persisted to localStorage (key: `ssf-transmitter-config`).
- Password-type input with show/hide toggle in Section 01 (Configuration card), below the Okta Domain field.
- New UI section between Key Management and Transmission: "Register Provider". Contains:
  - Provider name input (defaults to "SSF Transmitter")
  - "Create Provider in Okta" button — disabled until domain, API token, and keys all exist.
  - Success state: shows provider ID, "ACTIVE" badge.
  - Error state: shows Okta error message inline.
- Provider registration status persisted to localStorage so it survives page reloads.

### Security

API token stored only in browser localStorage. Sent to our API route which proxies it to Okta — never logged or persisted server-side.

## Feature 3: Guided Setup Stepper

### Design

Horizontal progress bar at the top of the left column, below SessionStats.

Four steps:
1. **Configure** — Complete when `oktaDomain` and `subjectEmail` are non-empty
2. **Generate Keys** — Complete when keys exist and JWKS is being served
3. **Register Provider** — Complete when provider is created in Okta (stored in localStorage)
4. **Send Events** — The final destination; always available once steps 1-2 are done

### Visual Treatment

- Numbered circles (1-4) connected by horizontal lines
- Completed: green checkmark replaces number, line turns green
- Current (first incomplete): highlighted/pulsing border
- Future: dimmed, gray

### Behavior

- Clicking a completed or current step smooth-scrolls to that card
- Non-blocking — users can skip steps or work out of order
- Step 3 (Register Provider) shows "(optional)" label since users may have already registered via Admin Console

### Component

New `SetupStepper.tsx` component. Receives completion booleans as props from `page.tsx`. Pure presentational — no state of its own.

## Files Changed

### New Files
- `app/api/jwks/route.ts` — GET/POST for JWKS hosting
- `app/.well-known/ssf-configuration/route.ts` — GET for SSF well-known config
- `app/api/create-provider/route.ts` — POST proxy to Okta SSF Receiver API
- `app/components/SetupStepper.tsx` — Stepper progress indicator

### Modified Files
- `app/page.tsx` — Add API token state, provider registration state, stepper integration, remove npoint.io flow, auto-push keys to /api/jwks
- `app/globals.css` — Stepper styles
- `CLAUDE.md` — Document new routes and setup flow

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Next.js 16 application that simulates real security vendor signals to Okta Identity Threat Protection. Acts as an SSF (Shared Signals Framework) **Transmitter** — generates RSA keys, signs Security Event Tokens (SETs) as JWTs, and POSTs them to Okta's Security Events API. Used by Okta Solutions Engineers to demo ITP without relying on real EDR endpoint polling.

10 security vendor profiles (CrowdStrike, Zscaler, Palo Alto, SOAR/CAEP, etc.), 39 event types, 5 pre-built scenarios.

## Development Commands

```bash
npm run dev          # Dev server at http://localhost:3000 (Turbopack)
npm run build        # Production build
npm start            # Production server
npm run lint         # ESLint (includes React Compiler rules)
npm test             # Vitest: payload snapshots, Okta schema rules, key store
```

`vitest` was installed with `--legacy-peer-deps` (its optional `@types/node` peer conflicts with the pinned `@types/node@20`).

## Architecture

### Single-Page Client App

The entire UI lives in `app/page.tsx` — a `'use client'` component that owns all application state. There is no routing beyond the single page. State is managed via `useState` hooks (no external state library). Configuration and transmission history persist to localStorage with debounced writes.

**localStorage keys:**
- `ssf-transmitter-config` — Okta domain, issuer URL, subject email, provider, risk level, theme, JWKS URL, API token, provider registration status
- `ssf-transmission-history` — last 100 transmission records
- `ssf-risk-tracker` — last risk level sent per subject email (drives `previous_level`)

**sessionStorage:** `ssf-transmitter-keys` — the generated keypair, so a reload doesn't force re-registration. The config also persists a random `tenantId` per browser.

### API Routes (Server-Side)

Next.js API routes:

- **`app/api/transmit/route.ts`** (POST) — Core endpoint. Imports the private key via `jose.importPKCS8`, builds the SET payload from provider/event config (with optional `previousLevel`, `reasonAdmin`, `reasonUser` context) or a custom payload, signs with `jose.SignJWT`, and POSTs to `https://{oktaDomain}/security/api/v1/security-events` with `Content-Type: application/secevent+jwt`. Returns the signed JWT and parsed Okta error details on failure.
- **`app/api/jwks/route.ts`** (GET/POST) — POST accepts `{ kid, publicJwk, tenantId? }` and stores the key via `app/lib/store.ts` (rejects JWKs containing `d`). GET serves the legacy single-tenant key set.
- **`app/api/jwks/[tenant]/route.ts`** (GET) — Per-tenant JWKS (current + previous key).
- **`app/t/[tenant]/.well-known/ssf-configuration/route.ts`** (GET) — Per-tenant SSF discovery doc: `{ issuer: {app}/t/{tenant}, jwks_uri: {app}/api/jwks/{tenant} }`. This is what one-click registration gives Okta.
- **`app/.well-known/ssf-configuration/route.ts`** (GET) — Legacy discovery doc (issuer = app origin) for providers registered before tenants existed.
- **`app/api/create-provider/route.ts`** (POST) — Proxies a call to `POST /api/v1/security-events-providers` on the user's Okta domain using their SSWS API token. Registers this app as an SSF provider via the well-known URL.
- **`app/api/verify-jwks/route.ts`** (POST) — Fetches a user-provided JWKS URL and checks that it contains a key matching the expected `kid`. Used for pre-flight validation before transmitting.
- **`app/api/test-connection/route.ts`** (POST) — Sends a HEAD request to the Okta security events endpoint to verify reachability. Sanitizes `-admin` suffix and trailing slashes from the domain.

### Data Model

Provider and event definitions live in `app/config/`:
- **`providers.ts`** — `PROVIDERS` record keyed by provider ID. Each provider has `events[]` where each event has a `buildPayload(email, timestamp, riskLevel, context?)` function that returns the SET `events` claim. `category` (`risk` | `session` | `credential` | `lifecycle`) groups buttons by the Okta policy surface; `experimental: true` marks events not yet confirmed against a live tenant (shown as UNVERIFIED).
- **`scenarios.ts`** — Pre-built multi-step chains referencing provider/event IDs with inter-step delays, optional per-step reason overrides and presenter `note`s.

Types are in `app/types/` — `SecurityProvider`, `SecurityEvent`, `RiskLevel`, `TransmissionRecord`, `QueuedEvent`, `Scenario`, `ScenarioExecutionState`.

### Key Generation Flow

1. Browser generates RS256 key pair via `jose.generateKeyPair('RS256', { extractable: true })` in `app/utils/crypto.ts`
2. Private key exported as PKCS8 PEM, kept in sessionStorage for the browser session
3. Public key auto-published to `/api/jwks/{tenant}` — no external hosting needed
4. Issuer URL auto-set to `{origin}/t/{tenant}`. Switching vendors keeps it (vendor default issuers only apply to manually created streams)
5. On transmit, PEM is sent to the server API route for signing

### Setup Flow

The app features a 4-step guided setup with a `SetupStepper` progress bar:
1. **Configure** — Enter Okta domain, target email, and optionally an API token
2. **Generate Keys** — Creates RSA key pair and auto-hosts JWKS
3. **Register Provider** (optional) — One-click registration via Okta SSF Receiver API
4. **Send Events** — Transmit security signals

### Components

All in `app/components/`. Notable ones: `SetupStepper` (4-step progress indicator), `ProviderSelector` (vendor switcher that updates issuer URL), `EventButtonGrid` (event action buttons), `ScenarioRunner` (multi-step attack automation with delays), `BulkSender` (event queue), `CustomEventBuilder` (freeform JSON payload), `TransmissionHistory` (log with replay), `PayloadPreview` (JWT inspection modal).

## React Compiler

Enabled in `next.config.ts` with `reactCompiler: true`. ESLint enforces `react-compiler/react-compiler: "error"`. Avoid patterns that break compiler assumptions: direct DOM manipulation, mutating props, non-idiomatic ref usage in render.

## Key Technical Constraints

### JWT / SET Requirements

- **Header**: `{ alg: 'RS256', kid: <keyId>, typ: 'secevent+jwt' }`
- **Payload**: `{ iss, iat, jti, aud, events }`
- **Audience (`aud`)** must be exactly `https://{oktaDomain}` — no trailing slash, no `-admin` suffix. See `app/api/transmit/route.ts:24-34` for hostname sanitization.

### Risk Event Payload Rules

`previous_level` comes from the client-side risk tracker (last level sent to that subject), falling back to `PREVIOUS_LEVEL_MAP`. Only `category: 'risk'` events update the tracker.

The `user-risk-change` event (`OKTA_RISK_SCHEMA`) has strict field requirements enforced by Okta:
- `initiating_entity` must be `"policy"` — not custom vendor names
- `reason_admin` and `reason_user` must be localized objects: `{ "en": "..." }`
- `subject.user.format` must be `"email"`

See `buildRiskPayload()` in `app/config/providers.ts`. CAEP events use `buildCaepPayload()` / `buildCaepRiskLevelPayload()` with the same `subject.user` email format.

### Policy surfaces

Everything this app sends drives **Entity Risk Policy**. **Session Protection Policy** reacts to Okta-observed session context changes (`user.session.context.change`) and cannot be triggered by a SET. Keep the two distinct in UI copy.

### JWKS Hosting

`app/lib/store.ts` stores keys in Upstash Redis when `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN` (or `KV_REST_API_URL`/`KV_REST_API_TOKEN`) are set, otherwise in memory (local dev). Keys expire after 30 days; the page re-publishes its key on load, so an in-memory restart self-heals. For external hosting, the public key can still be copied from the Key Management section.

## Common Errors

| Error | Fix |
|-------|-----|
| `invalid_audience` | Remove `-admin` suffix and trailing slash from Okta domain |
| `jwks_url is not valid` / `verification_failed` | App must be publicly reachable; on serverless configure Upstash Redis; ensure `kid` matches |
| Risk events not triggering ITP | Create Entity Risk Policy in Okta (Security > Entity Risk Policy) |
| `initiating_entity: Not one of the allowed values` | Use `"policy"`, not vendor names, in `app/config/providers.ts` |

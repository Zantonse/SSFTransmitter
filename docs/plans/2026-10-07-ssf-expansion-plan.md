# SSF Transmitter — Improvement Plan (2026-10)

## Context

The tool lives in **`Zantonse/SSFTransmitter`** (Next.js 16 / React 19 / jose; last commit 2026-03-04). `Zantonse/SSF-Transmitter` is an older Feb prototype (`okta-ssf-visual/`). Today the tool only does inbound simulation: 9 vendors, 31 events (27 of them `okta/user-risk-change`, 4 RISC lifecycle), and 3 scenarios, all driving **Entity Risk Policy**.

The user's baseline priorities are: (1) a session-level CAEP event, (2) quick wins on payload variety, (3) the outbound SSF / SIEM receiver as the stretch goal. Reading the code turned up corrections and existing bugs that should come first.

### Corrections to the baseline (from code + docs research)
- **Session Protection Policy can't be triggered by an inbound SET.** `user.session.context.change` and `policy.auth_reevaluate.*` are **System Log event types Okta emits** when *it* sees IP or device drift in real session traffic. A transmitter cannot send them. What a transmitter *can* do at session level is send **CAEP `session-revoked`** (and possibly `assurance-level-change` / `risk-level-change`). So the "session" addition is reframed as *external-session-revocation + entity risk*, and Session Protection is demoed alongside it via real traffic (e.g. a VPN switch mid-session). Put that one-liner in the README and UI.
- **Namespace bug:** `session-revoked` is a **CAEP** event (`https://schemas.openid.net/secevent/caep/event-type/session-revoked`), but `providers.ts` and `CustomEventBuilder.tsx:26` send it under the **RISC** namespace. Confirm which namespace Okta accepts and fix it.
- **Okta's receiver list is narrower than the full CAEP spec.** Public docs list CAEP `session-revoked`, `credential-change`, `assurance-level-change`, `risk-level-change` plus Okta `user-risk-change`. `device-compliance-change` / `device-risk-change` are **not confirmed** as accepted. Every new type gets a tenant smoke test before it ships, and anything Okta rejects stays out of the UI. Docs (developer.okta.com, help.okta.com) were blocked from this sandbox, so this list comes from search snippets.
- **Outbound SSF is real and narrow.** Okta's SSF Transmitter pushes only CAEP **`session-revoked`** (from `user.session.end`) and **`credential-change`** (MFA factor changes, password reset/update). It is configured via the SSF Transmitter API (`/api/v1/ssf/stream`, verify the path). That narrowness shapes Phase 3.

## Phase 0 — Fix foundations (do first, ~0.5 day)

1. **Durable, per-user JWKS.** In `app/api/jwks/route.ts` the keys live in a module-level `Map` that is `clear()`ed on every POST. On Vercel this breaks in two ways: a cold or other instance serves `{keys: []}` (causing intermittent `verification_failed`), and two SEs sharing the deployment overwrite each other's keys.
   - Fix: move the key store to **Upstash Redis via the Vercel Marketplace** (`@upstash/redis`), with keys namespaced by tenant id = hash(oktaDomain + issuer). Serve `GET /api/jwks/[tenant]` and `/.well-known/ssf-configuration` per tenant (issuer becomes `https://<app>/t/<tenant>`). Keep a local-dev fallback to the in-memory Map when no Redis env is set.
   - Persist the keypair across reloads (private PEM in `sessionStorage` at minimum) so a page refresh doesn't force re-registering in Okta.
2. **Correct `previous_level`.** `PREVIOUS_LEVEL_MAP` in `app/config/providers.ts` always reports `previous: low`, so the "Risk Escalation" scenario claims low→medium, then low→high. Track the last level sent per subject (client state in `page.tsx`, passed to `/api/transmit` as `previousLevel`) and fall back to the map.
3. **Fix the session-revoked namespace** (see above) and add a `caep` schema constants block in `providers.ts`.
4. **Refresh the README.** It still says to host the JWKS on npoint.io, clones the old `SSF-Transmitter` URL, and lists only 3 of the 6 API routes. Sync it with `CLAUDE.md`.
5. **Add Vitest plus payload snapshot tests** for every `buildPayload` (there are no tests today). This is cheap insurance for Okta's strict schema rules (`initiating_entity: "policy"`, localized reasons, `format: "email"`).

## Phase 1 — Session-level CAEP events (top recommendation, ~1 day)

Use the same pipeline: `SecurityEvent.buildPayload` → `/api/transmit` signs and POSTs. Nothing new on the transport side.

- `app/types/providers.ts`: extend `EventCategory` with `'session'` and `'credential'`. Let `buildPayload` take an optional context `{ sessionId?, previousLevel? }`.
- `app/config/providers.ts`: add `buildCaepPayload(schema, email, ts, extra)` next to `buildRiskPayload` / `buildLifecyclePayload`. Use the CAEP subject format (`{ format: "email", email }`, or a `complex` user+session subject if Okta accepts it), plus `event_timestamp` and optional `initiating_entity` / `reason_admin` / `reason_user`.
- New events, each gated on a tenant smoke test:
  - CAEP `session-revoked`: "SOC kills attacker session". Add it to Microsoft (Entra session revoke), CrowdStrike (Identity Protection), and a new **"Generic IdP / SOAR"** provider.
  - CAEP `credential-change`: "password reset by helpdesk / compromised credential rotated".
  - CAEP `assurance-level-change`: "user's MFA downgraded" (only if accepted).
  - CAEP `risk-level-change` (standard CAEP alternative to Okta's proprietary schema): a toggle that sends either form, to show standards interop (only if accepted).
- UI (`EventButtonGrid.tsx`): group buttons by category and give each a badge naming the **policy surface it drives**: *Entity Risk Policy*, *Session revocation*, or *Lifecycle*. Add an info callout explaining Entity Risk Policy vs. Session Protection Policy.
- `CustomEventBuilder.tsx`: add the CAEP schemas to the template dropdown.
- Add a "Verify in Okta" deep-link per event: a System Log query URL for `security.events.provider.receive_event` and `user.risk.detect` on the target user.

## Phase 2 — Richer scenarios (~1 day)

- **Correlated escalation:** one vendor raises one user low → medium → high with distinct, escalating `reason_admin` text (an "XDR incident timeline"). This depends on the Phase 0 `previous_level` fix. Add an optional **de-escalation** step (high → low, "incident closed"); it shows risk reset, and you can use it to empirically test the [NEEDS_SME] risk-decay question.
- **Session hijack response:** Proofpoint `phishing-clicked` (risk medium) → Defender `risky-signin` (high) → CAEP `session-revoked`.
- `app/types/scenarios.ts`: let `ScenarioStep` carry an optional `riskLevel` override, `reason` override, and `note` (presenter script line shown in `ScenarioRunner` while the step runs).
- Scenario Runner: add a "presenter notes" panel showing what to click in Okta Admin at each step.

## Phase 3 — Outbound SSF: mock SIEM/SOC receiver (stretch, ~3–4 days)

Goal: a closed-loop demo. The transmitter raises risk → ITP runs Universal Logout → Okta emits `user.session.end` → **Okta's SSF Transmitter pushes CAEP `session-revoked` to our mock receiver**, which renders it live as a "SIEM feed".

- **Receiver endpoint** `app/api/receiver/[streamId]/route.ts` (POST, `application/secevent+jwt`):
  - Check the `Authorization` header against the stream's secret.
  - Verify the JWT with `jose.createRemoteJWKSet` using the `jwks_uri` from `https://{oktaDomain}/.well-known/ssf-configuration`, and check `aud` against our receiver URL.
  - Store the decoded SET in Redis (from Phase 0), as a list per stream capped at 200 entries.
  - Return `202`, per RFC 8935.
- **Stream setup** `app/api/ssf-stream/route.ts`: proxy Okta's SSF Transmitter API using the SSWS token already handled in `create-provider/route.ts` (reuse that pattern). Create the stream with push delivery to `/api/receiver/{streamId}` plus a generated auth header, requesting `session-revoked` and `credential-change`. Also support GET/DELETE for stream status and teardown. Mirror it in the setup flow as optional step 5 in `SetupStepper`.
- **UI** `app/components/ReceiverFeed.tsx`: a live table that polls `/api/receiver/[streamId]?since=` every 2 s (SSE is unreliable on Vercel serverless). Show event type, subject, reason, and a decoded-JWT drawer that reuses `PayloadPreview.tsx`. Add a "Correlate" view that pairs each outbound SET with the inbound transmission that caused it (by subject + time window), with lag in seconds. That lag is the demo moment.
- **Fallbacks:** local dev needs a public URL for Okta to push to. Document `ngrok`/`cloudflared`, and auto-detect localhost so the UI can warn about it. Okta also supports a stream verification event, so add a "Send verification" button for a dry run without logging anyone out.
- Positioning: keep this in the same app as a second tab ("Inbound to Okta" / "Outbound from Okta") rather than a separate repo. It reuses keys, config, Redis, and the UI shell.

## Out of scope (agree with baseline)
ThreatInsight and native Behavior Detection (impossible travel, brute force, breached credentials) come from Okta's own auth traffic, not SETs, so this tool doesn't touch them. At most, add a README pointer to System Log queries.

## Open items to resolve in-tenant (not blockers)
- Which CAEP types Okta's receiver accepts (smoke test each before enabling its button).
- Whether `session-revoked` must use the CAEP or the RISC namespace.
- Risk decay window (use the Phase 2 de-escalation scenario to observe it).
- Risk Providers vs. Security Event Providers naming, and Network Zones × risk rules: [NEEDS_SME], keep out of customer-facing copy.

## Critical files
- `app/config/providers.ts`, `app/types/providers.ts` (payload builders, categories)
- `app/api/transmit/route.ts` (pass `previousLevel` / context)
- `app/api/jwks/route.ts`, `app/.well-known/ssf-configuration/route.ts` (Redis, per-tenant)
- `app/config/scenarios.ts`, `app/types/scenarios.ts`, `app/components/ScenarioRunner.tsx`
- `app/components/EventButtonGrid.tsx`, `CustomEventBuilder.tsx`, `SetupStepper.tsx`, `app/page.tsx`
- New: `app/api/receiver/[streamId]/route.ts`, `app/api/ssf-stream/route.ts`, `app/components/ReceiverFeed.tsx`, `app/lib/store.ts`

## Verification
- `npm run lint && npm run build`, plus `npx vitest` snapshot tests of every payload builder.
- Tenant smoke test per new event: transmit, get a `202` from Okta, then check System Log for `security.events.provider.receive_event` (and `user.risk.detect` for risk events).
- JWKS: deploy to Vercel and, from two browsers with different domains, confirm each `/api/jwks/[tenant]` returns only its own key across cold starts.
- Escalation scenario: decoded SETs show previous_level progressing low → medium → high.
- Phase 3: create a stream, click "Send verification", and see it in the feed. Then fire a high-risk event at a user with ITP Universal Logout and see the correlated CAEP `session-revoked` arrive in the feed.

## Status
- Phases 0–2: implemented (this branch). Storage: Upstash Redis with in-memory fallback.
- Phase 3: deferred to a follow-up PR.
- CAEP events ship tagged UNVERIFIED (`experimental: true`) pending a live-tenant smoke test.

## Suggested sequencing
Phase 0 → Phase 1 → Phase 2 is one PR series (~2.5 days). Phase 3 is a separate PR after the Redis store from Phase 0 lands.

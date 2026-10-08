# SSF Transmitter

A production-grade tool that simulates real security vendor signals to Okta Identity Threat Protection — live, in the demo.

## What It Is

SSF Transmitter is a Next.js application that generates, signs, and transmits standards-compliant Security Event Tokens (SETs) to Okta's Security Events API. It does exactly what vendors like CrowdStrike, Zscaler, and Palo Alto do in production through the Shared Signals Framework (SSF) — letting Solutions Engineers fire real signed tokens and watch Okta respond in real time.

## Why It Matters

The most compelling ITP demo moment is showing a security vendor detect a threat and Okta respond instantly — elevating user risk, triggering Universal Logout, revoking sessions across every connected app. But the traditional EDR integration relies on endpoint polling through Okta Verify, which is fragile and frequently fails during live demos.

SSF Transmitter eliminates that fragility. No endpoint dependencies. No hoping the agent polls at the right moment. The demo just works.

## How It Works

1. **Key Generation** — RSA-256 keypairs are generated in the browser using the Web Crypto API. The public key is published automatically to a per-browser JWKS endpoint hosted by the app (`/api/jwks/{tenant}`). No external JWKS hosting is needed.

2. **Configuration** — Provide your Okta domain, select a security vendor, and specify a target user email.

3. **Token Signing** — The server constructs a SET payload matching Okta's exact schema requirements (`user-risk-change` for ITP triggers, CAEP events for session/credential signals, RISC for lifecycle) and signs it as a JWT with the `secevent+jwt` type header per RFC 8417.

4. **Transmission** — The signed token is POSTed to `https://{oktaDomain}/security/api/v1/security-events`. Okta validates the signature, processes the risk signal, and — with an Entity Risk Policy configured — triggers automated response actions like Universal Logout.

## Supported Vendors

| Vendor | Category | Events |
|--------|----------|--------|
| **CrowdStrike Falcon** | EDR / MDR | Malware Detected, Suspicious Process, IOC Match, Credential Theft |
| **Zscaler ZIA** | CASB / DLP | DLP Violation, Malware Download Blocked, Suspicious Cloud Activity |
| **Palo Alto Cortex XDR** | XDR | C2 Communication, Lateral Movement, Ransomware Behavior |
| **Microsoft Defender** | Entra ID / Defender | Threat Detected, Suspicious Activity, Risky Sign-In, Impossible Travel |
| **SentinelOne** | EPP / EDR | Threat Mitigated, Malicious File, Behavioral AI Alert |
| **Netskope** | SASE / DLP | Data Exfiltration, Risky App Usage, Policy Violation |
| **Proofpoint** | Email Security | Phishing Clicked, Malware Attachment, BEC Attempt, VAP Targeted |
| **Cisco Secure Endpoint** | EDR | Malware Executed, Exploit Prevented, Threat Quarantined |
| **SOAR / IdP Response** | OpenID CAEP | Session Revoked, Compromised Password Rotated, MFA Assurance Downgraded, Risk Level Change (CAEP) |
| **RISC Lifecycle** | OpenID Standard | Session Revoked, Credential Change Required, Account Disabled |

CrowdStrike and Microsoft also include a CAEP **session-revoked** event (Identity Protection / Entra session revoke).

**10 vendors. 39 event types. 5 pre-built scenarios.**

### Entity Risk Policy vs. Session Protection Policy

Every signal this tool sends feeds **entity risk** and drives the **Entity Risk Policy**: risk changes plus CAEP session and credential events. **Session Protection Policy** is a separate surface. It reacts to IP or device changes that Okta itself observes in a live session (System Log `user.session.context.change`), and no transmitter can trigger it. Demo it alongside this tool by switching networks (e.g. a VPN) mid-session.

### Unverified CAEP events

Events tagged **UNVERIFIED** in the UI (all CAEP events) follow the OpenID CAEP 1.0 spec and the subject format Okta accepts for `user-risk-change`. They have not yet been confirmed against a live tenant. Before using one in a customer demo:

1. Send it once from the Transmission card.
2. Confirm Okta answers `202` (Transmission History) and that System Log shows `security.events.provider.receive_event`.
3. If Okta accepts it, remove `experimental: true` from the event in `app/config/providers.ts`.

The legacy **RISC Session Revoked** event uses the RISC namespace. In the OpenID specs `session-revoked` is a CAEP event, so prefer the CAEP version once you've verified it.

## Features

- **Real JWT Signing** — Standards-compliant SETs signed with RS256
- **Browser RSA Crypto** — Key generation via Web Crypto API, no server-side secrets
- **Scenario Automation** — Pre-built multi-step attack chains with presenter notes (Compromised User, Risk Escalation, Multi-Vector Attack, XDR Incident Timeline, Session Hijack Response)
- **Accurate Risk Transitions** — `previous_level` reflects the last level sent to each user, so escalations read low → medium → high in Okta
- **Auto-Hosted JWKS** — Per-browser JWKS + SSF discovery document; one-click provider registration in Okta
- **Bulk Event Sending** — Queue multiple events with configurable delays
- **Payload Preview** — Inspect the exact JWT before transmission
- **Transmission History** — Replay past events, filter and search
- **Custom Event Builder** — Freeform JSON for arbitrary event schemas
- **Config Persistence** — Settings saved across sessions via localStorage
- **Dark / Light Mode** — Full theme support

## Quick Start

New to the tool? Open **How this works** at the top of the app. It explains the signal flow, what you need in Okta first, and the key terms, and each section has a one-line explainer of what it does.

### 1. Install & Run

```bash
git clone https://github.com/Zantonse/SSFTransmitter.git
cd SSFTransmitter
npm install
npm run dev
```

Open **http://localhost:3000**. Okta must be able to reach the app's JWKS, so for a live tenant either deploy it (e.g. Vercel) or expose your dev server with `ngrok` / `cloudflared`.

### 2. Configure

Enter your **Okta domain** (e.g. `dev-123456.okta.com`, no `-admin`), the **target user's email**, and optionally an **Okta API token** (needed only for one-click registration).

### 3. Generate Keys

Click **Generate Keys**. The public key is published automatically to `/api/jwks/{tenant}`, and the Issuer URL is set to `{app}/t/{tenant}`. Each browser gets its own tenant ID, so several SEs can share one deployment without overwriting each other's keys. Keys survive page reloads for the browser session.

### 4. Register the Provider in Okta

- **One click (recommended):** with an API token set, click **Register Provider**. This registers `{app}/t/{tenant}/.well-known/ssf-configuration` with Okta.
- **Manual:** in Okta Admin go to **Security > Device Integrations > Receive shared signals > Create Stream** and use the Issuer URL and JWKS URL shown in the app.

### 5. Configure Entity Risk Policy (Required for ITP)

1. Navigate to: **Security > Entity Risk Policy**
2. Create or edit a policy that responds to external risk signals
3. Configure actions (e.g., Universal Logout, step-up MFA) when risk level changes

### 6. Send Events

Pick a vendor and click any event, or run a scenario from the Scenarios tab.

### Deploying (shared JWKS storage)

Serverless instances don't share memory. On Vercel, add **Upstash Redis** from the Vercel Marketplace so published keys survive cold starts and are visible to every instance. The app reads `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` (or `KV_REST_API_URL` / `KV_REST_API_TOKEN`). Without them it falls back to in-memory storage, which is fine for local dev.

## Configuration Fields

| Field | Description | Example |
|-------|-------------|---------|
| **Okta Domain** | Your Okta org domain (no `https://` or `-admin`) | `dev-123456.okta.com` |
| **Security Provider** | The simulated security vendor | CrowdStrike Falcon |
| **Issuer URL** | Must match Okta stream configuration. Auto-set to the tenant issuer after key generation; kept when you switch vendors | `https://ssf.example.app/t/3f9a…` |
| **Target Subject** | Email of the user to apply the risk signal to | `user@company.com` |

## Verifying Events in Okta

### System Log

Navigate to **Reports > System Log** and search:

```
eventType eq "security.events.provider.receive_event"
```

You'll see entries showing the provider name, event details, and risk level changes.

### User Risk

After sending a HIGH severity event:

1. Go to **Directory > People**
2. Select the target user
3. Check their **Risk Level** in the profile

Or view **Reports > User Risk Report** for aggregated data.

## Architecture

```
app/
├── page.tsx                         # Main dashboard UI
├── globals.css                      # Theme variables & styling
├── .well-known/ssf-configuration/   # Legacy single-tenant discovery doc
├── t/[tenant]/.well-known/ssf-configuration/  # Per-tenant discovery doc
├── api/
│   ├── transmit/route.ts            # SET signing & transmission
│   ├── jwks/route.ts                # Publish key (POST); legacy JWKS (GET)
│   ├── jwks/[tenant]/route.ts       # Per-tenant JWKS
│   ├── create-provider/route.ts     # One-click Okta provider registration
│   ├── verify-jwks/route.ts         # JWKS validation
│   └── test-connection/route.ts     # Okta endpoint reachability
├── lib/
│   ├── store.ts                     # JWKS store (Upstash Redis or in-memory)
│   └── http.ts                      # Shared route helpers
├── utils/crypto.ts                  # RSA key generation
├── config/
│   ├── providers.ts                 # Vendor definitions + payload builders
│   ├── providers.test.ts            # Payload snapshot & schema-rule tests
│   └── scenarios.ts                 # Pre-built scenarios
├── types/                           # Provider, history, bulk, scenario types
└── components/                      # UI components (EventButtonGrid, ScenarioRunner, …)
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_audience` | Audience claim mismatch | Ensure Okta domain has no `-admin` suffix or trailing slash |
| `jwks_url is not valid` | Okta can't reach your JWKS | Make sure the app is publicly reachable (deployed or tunneled) |
| `verification_failed` | Signature doesn't match / key missing | On serverless, configure Upstash Redis; otherwise reload the page to re-publish the key |
| Issuer mismatch | SET `iss` differs from the registered provider | Use the tenant Issuer URL shown after key generation |
| Events not triggering ITP | No Entity Risk Policy | Create a policy under Security > Entity Risk Policy |
| `initiating_entity` error | Using custom string | Use `"policy"` as the value, not vendor names |

## Tech Stack

- **Next.js 16** with Turbopack
- **React 19** with React Compiler
- **TypeScript** in strict mode
- **jose** for JWT signing & cryptography
- **Tailwind CSS 4** for styling
- **Web Crypto API** for browser-side RSA key generation

## Development

```bash
npm run dev       # Start dev server
npm run build     # Build for production
npm run lint      # Run ESLint
npm test          # Run Vitest (payload snapshots, schema rules, key store)
```

After intentionally changing a payload, update snapshots with `npx vitest run -u` and review the diff.

## License

MIT License - See [LICENSE](LICENSE) for details.

---

Built with [Claude Code](https://claude.ai/code)

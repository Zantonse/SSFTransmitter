'use client';

interface HowItWorksProps {
  open: boolean;
  onToggle: (open: boolean) => void;
}

const FLOW = [
  { title: 'This app', detail: 'plays a security vendor' },
  { title: 'Signed event', detail: 'a Security Event Token about one user' },
  { title: 'Okta verifies', detail: 'checks the signature with your public key' },
  { title: 'User risk ↑', detail: 'shown on the user in Okta' },
  { title: 'Policy acts', detail: 'Entity Risk Policy: logout, MFA…' },
];

const PREREQS = [
  'An Okta org with Identity Threat Protection',
  'An Entity Risk Policy rule that acts on High risk (Security > Entity Risk Policy)',
  'The email of a real test user in that org',
  'An admin API token — only for one-click provider registration (step 3)',
];

const GLOSSARY = [
  ['SET', 'Security Event Token — a signed JWT carrying one security event.'],
  ['Public key / JWKS', 'Published by this app so Okta can prove each event came from you.'],
  ['Issuer', 'The ID Okta knows this transmitter by. Auto-set when you generate keys.'],
  ['Security Events Provider', 'The entry in Okta that says "trust events from this issuer."'],
  ['Risk vs. CAEP events', 'Okta risk events set a risk level; CAEP events are open-standard signals like "session revoked."'],
];

export default function HowItWorks({ open, onToggle }: HowItWorksProps) {
  return (
    <details
      className="collapsible-tip how-it-works"
      open={open}
      onToggle={(e) => onToggle(e.currentTarget.open)}
    >
      <summary>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <circle cx="12" cy="12" r="10" />
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
        How this works
      </summary>
      <div className="tip-content">
        <p>
          This tool stands in for a security vendor like CrowdStrike or Zscaler. When you click an event, it sends Okta a
          signed message saying &ldquo;this user looks compromised.&rdquo; Okta raises the user&apos;s risk, and your Entity
          Risk Policy responds live, e.g. with Universal Logout — no real endpoint agent needed.
        </p>

        <ol className="how-it-works-flow" aria-label="How a signal flows">
          {FLOW.map((step) => (
            <li key={step.title}>
              <span className="how-it-works-flow-title">{step.title}</span>
              <span className="how-it-works-flow-detail">{step.detail}</span>
            </li>
          ))}
        </ol>

        <div className="how-it-works-columns">
          <div>
            <p className="how-it-works-heading">Before you start (in Okta)</p>
            <ul>
              {PREREQS.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <div>
            <p className="how-it-works-heading">Terms</p>
            <dl>
              {GLOSSARY.map(([term, definition]) => (
                <div key={term}>
                  <dt>{term}</dt>
                  <dd>{definition}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>

        <p>Then work through the four steps below, top to bottom. Each section explains what it does.</p>
      </div>
    </details>
  );
}

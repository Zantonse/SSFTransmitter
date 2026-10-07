import { Scenario } from '../types/scenarios';

export const SCENARIOS: Scenario[] = [
  {
    id: 'compromised-user',
    name: 'Compromised User',
    description: 'Endpoint compromise leads to data exfiltration and phishing — a cascading attack across three vendors.',
    steps: [
      { providerId: 'crowdstrike', eventId: 'malware-detected', riskLevel: 'high', delayAfterMs: 2000 },
      { providerId: 'zscaler', eventId: 'dlp-violation', riskLevel: 'high', delayAfterMs: 2000 },
      { providerId: 'proofpoint', eventId: 'phishing-clicked', riskLevel: 'high', delayAfterMs: 0 },
    ],
  },
  {
    id: 'risk-escalation',
    name: 'Risk Escalation',
    description: 'Same threat type reported three times with escalating severity — watch the risk level climb.',
    steps: [
      { providerId: 'crowdstrike', eventId: 'suspicious-process', riskLevel: 'low', delayAfterMs: 2000 },
      { providerId: 'crowdstrike', eventId: 'suspicious-process', riskLevel: 'medium', delayAfterMs: 2000 },
      { providerId: 'crowdstrike', eventId: 'suspicious-process', riskLevel: 'high', delayAfterMs: 0 },
    ],
  },
  {
    id: 'multi-vector-attack',
    name: 'Multi-Vector Attack',
    description: 'Attacker gains access, moves laterally, steals credentials, then exfiltrates data across four security layers.',
    steps: [
      { providerId: 'microsoft', eventId: 'risky-signin', riskLevel: 'medium', delayAfterMs: 2000 },
      { providerId: 'paloalto', eventId: 'lateral-movement', riskLevel: 'high', delayAfterMs: 2000 },
      { providerId: 'crowdstrike', eventId: 'credential-theft', riskLevel: 'high', delayAfterMs: 2000 },
      { providerId: 'netskope', eventId: 'data-exfiltration', riskLevel: 'high', delayAfterMs: 0 },
    ],
  },
  {
    id: 'xdr-incident-timeline',
    name: 'XDR Incident Timeline',
    description: 'One XDR incident escalates the same user low → medium → high as evidence accumulates, then closes and resets risk.',
    steps: [
      {
        providerId: 'paloalto',
        eventId: 'c2-communication',
        riskLevel: 'low',
        delayAfterMs: 3000,
        reasonAdmin: 'Cortex XDR incident #4127 opened: beaconing to newly registered domain (score 32)',
        reasonUser: 'Unusual network activity was detected from your device',
        note: 'Show the user in Directory > People: risk is LOW, no policy action yet.',
      },
      {
        providerId: 'paloalto',
        eventId: 'c2-communication',
        riskLevel: 'medium',
        delayAfterMs: 3000,
        reasonAdmin: 'Cortex XDR incident #4127 updated: credential dumping tool observed on same host (score 68)',
        reasonUser: 'Suspicious activity was detected on your device',
        note: 'System Log: user.risk.detect shows previous_level low → medium.',
      },
      {
        providerId: 'paloalto',
        eventId: 'c2-communication',
        riskLevel: 'high',
        delayAfterMs: 3000,
        reasonAdmin: 'Cortex XDR incident #4127 escalated: lateral movement to finance server confirmed (score 94)',
        reasonUser: 'Your account was signed out to protect your data',
        note: 'Entity Risk Policy fires at HIGH: show Universal Logout in the user’s browser.',
      },
      {
        providerId: 'paloalto',
        eventId: 'c2-communication',
        riskLevel: 'low',
        delayAfterMs: 0,
        reasonAdmin: 'Cortex XDR incident #4127 closed: host reimaged and credentials rotated',
        reasonUser: 'The security issue on your device has been resolved',
        note: 'Risk returns to LOW — the user can sign back in. Shows the XDR can de-escalate, not just escalate.',
      },
    ],
  },
  {
    id: 'session-hijack-response',
    name: 'Session Hijack Response',
    description: 'Phishing click, then a risky sign-in from the stolen session, then the SOC revokes the session via CAEP.',
    steps: [
      {
        providerId: 'proofpoint',
        eventId: 'phishing-clicked',
        riskLevel: 'medium',
        delayAfterMs: 3000,
        note: 'Proofpoint reports the click — risk goes to MEDIUM.',
      },
      {
        providerId: 'microsoft',
        eventId: 'risky-signin',
        riskLevel: 'high',
        delayAfterMs: 3000,
        note: 'Entra sees the token replayed from a new location — risk HIGH, Entity Risk Policy responds.',
      },
      {
        providerId: 'soar',
        eventId: 'caep-session-revoked',
        riskLevel: 'high',
        delayAfterMs: 0,
        note: 'SOAR playbook sends a standards-based CAEP session-revoked. Show security.events.provider.receive_event in System Log.',
      },
    ],
  },
];

import { SecurityProvider, RiskLevel, PayloadContext } from '../types/providers';

// Event schemas
export const OKTA_RISK_SCHEMA = 'https://schemas.okta.com/secevent/okta/event-type/user-risk-change';
export const RISC_SESSION_REVOKED = 'https://schemas.openid.net/secevent/risc/event-type/session-revoked';
export const RISC_CREDENTIAL_CHANGE = 'https://schemas.openid.net/secevent/risc/event-type/credential-change-required';
export const RISC_ACCOUNT_DISABLED = 'https://schemas.openid.net/secevent/risc/event-type/account-disabled';
export const RISC_ACCOUNT_CREDENTIAL_CHANGE = 'https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required';

// OpenID CAEP 1.0 event types. session-revoked is defined by CAEP, not RISC.
export const CAEP_SESSION_REVOKED = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';
export const CAEP_CREDENTIAL_CHANGE = 'https://schemas.openid.net/secevent/caep/event-type/credential-change';
export const CAEP_ASSURANCE_LEVEL_CHANGE = 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change';
export const CAEP_RISK_LEVEL_CHANGE = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';

// Fallback previous level when no earlier risk event was sent for the subject
const PREVIOUS_LEVEL_MAP: Record<RiskLevel, RiskLevel> = {
  high: 'low',
  medium: 'low',
  low: 'low', // When setting to low, we still use low as previous (no change scenario)
};

export function resolvePreviousLevel(currentLevel: RiskLevel, context?: PayloadContext): RiskLevel {
  return context?.previousLevel ?? PREVIOUS_LEVEL_MAP[currentLevel];
}

function emailSubject(email: string) {
  return {
    user: {
      format: 'email',
      email: email,
    },
  };
}

function buildRiskPayload(
  email: string,
  timestamp: number,
  reasonAdmin: string,
  reasonUser: string,
  currentLevel: RiskLevel = 'high',
  context?: PayloadContext
): Record<string, unknown> {
  return {
    [OKTA_RISK_SCHEMA]: {
      event_timestamp: timestamp,
      current_level: currentLevel,
      previous_level: resolvePreviousLevel(currentLevel, context),
      initiating_entity: 'policy',
      reason_admin: { en: context?.reasonAdmin ?? reasonAdmin },
      reason_user: { en: context?.reasonUser ?? reasonUser },
      subject: emailSubject(email),
    },
  };
}

// CAEP events share the SSF complex subject format Okta already accepts for user-risk-change,
// plus the optional CAEP common claims (initiating_entity, reason_admin, reason_user).
function buildCaepPayload(
  schema: string,
  email: string,
  timestamp: number,
  reasonAdmin: string,
  reasonUser: string,
  context?: PayloadContext,
  extra: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    [schema]: {
      event_timestamp: timestamp,
      initiating_entity: 'policy',
      reason_admin: { en: context?.reasonAdmin ?? reasonAdmin },
      reason_user: { en: context?.reasonUser ?? reasonUser },
      ...extra,
      subject: emailSubject(email),
    },
  };
}

function buildCaepRiskLevelPayload(
  email: string,
  timestamp: number,
  riskReason: string,
  currentLevel: RiskLevel,
  context?: PayloadContext
): Record<string, unknown> {
  return {
    [CAEP_RISK_LEVEL_CHANGE]: {
      event_timestamp: timestamp,
      principal: 'USER',
      current_level: currentLevel.toUpperCase(),
      previous_level: resolvePreviousLevel(currentLevel, context).toUpperCase(),
      risk_reason: context?.reasonAdmin ?? riskReason,
      subject: emailSubject(email),
    },
  };
}

function buildLifecyclePayload(
  email: string,
  timestamp: number,
  schema: string
): Record<string, unknown> {
  return {
    [schema]: {
      subject: {
        subject_type: 'email',
        email: email,
      },
      event_timestamp: timestamp,
    },
  };
}

export const PROVIDERS: Record<string, SecurityProvider> = {
  crowdstrike: {
    id: 'crowdstrike',
    name: 'CrowdStrike Falcon',
    defaultIssuer: 'https://falcon.crowdstrike.com',
    description: 'Endpoint detection and response platform',
    color: 'bg-red-600',
    events: [
      {
        id: 'malware-detected',
        label: 'Malware Detected',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Malware identified on user endpoint',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Malware detected on user endpoint by CrowdStrike Falcon',
            'Security software detected a threat on your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'suspicious-process',
        label: 'Suspicious Process',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Suspicious process execution detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Suspicious process execution detected on endpoint',
            'Unusual activity was detected on your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'ioc-match',
        label: 'IOC Match',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Indicator of compromise matched threat intelligence',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Indicator of compromise matched known threat intelligence',
            'A security threat was identified on your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'credential-theft',
        label: 'Credential Theft Attempt',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Credential theft attempt detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Credential theft attempt detected by CrowdStrike Falcon',
            'An attempt to steal your credentials was blocked',
            riskLevel,
            context
          ),
      },
      {
        id: 'idp-session-revoked',
        label: 'Identity Protection: Session Revoked',
        schema: CAEP_SESSION_REVOKED,
        severity: 'high',
        category: 'session',
        experimental: true,
        description: 'Falcon Identity Protection kills a suspected hijacked session (CAEP)',
        buildPayload: (email, timestamp, _riskLevel, context) =>
          buildCaepPayload(
            CAEP_SESSION_REVOKED,
            email,
            timestamp,
            'Falcon Identity Protection revoked session after detecting token reuse from an unmanaged host',
            'Your session was ended for security reasons',
            context
          ),
      },
    ],
  },
  zscaler: {
    id: 'zscaler',
    name: 'Zscaler ZIA',
    defaultIssuer: 'https://zsapi.zscaler.net',
    description: 'Cloud security and web gateway',
    color: 'bg-blue-600',
    events: [
      {
        id: 'dlp-violation',
        label: 'DLP Policy Violation',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Data loss prevention policy violation detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'DLP policy violation: sensitive data exfiltration attempted',
            'A data security policy was violated',
            riskLevel,
            context
          ),
      },
      {
        id: 'malware-blocked',
        label: 'Malware Download Blocked',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Attempted malware download was blocked',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Malware download attempt blocked by Zscaler ZIA',
            'A potentially harmful download was blocked',
            riskLevel,
            context
          ),
      },
      {
        id: 'suspicious-cloud',
        label: 'Suspicious Cloud Activity',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Suspicious cloud application activity detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Suspicious cloud application activity detected',
            'Unusual cloud activity was detected from your account',
            riskLevel,
            context
          ),
      },
    ],
  },
  paloalto: {
    id: 'paloalto',
    name: 'Palo Alto Cortex XDR',
    defaultIssuer: 'https://api.xdr.paloaltonetworks.com',
    description: 'Extended detection and response platform',
    color: 'bg-orange-600',
    events: [
      {
        id: 'c2-communication',
        label: 'C2 Communication Detected',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Command and control communication detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Command and control (C2) communication detected',
            'Suspicious network communication was detected from your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'lateral-movement',
        label: 'Lateral Movement',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Lateral movement behavior detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Lateral movement detected in network by Cortex XDR',
            'Suspicious network activity was detected from your account',
            riskLevel,
            context
          ),
      },
      {
        id: 'ransomware-behavior',
        label: 'Ransomware Behavior',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Ransomware-like behavior detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Ransomware behavior detected: mass file encryption attempt',
            'Potentially harmful file activity was detected on your device',
            riskLevel,
            context
          ),
      },
    ],
  },
  microsoft: {
    id: 'microsoft',
    name: 'Microsoft Defender',
    defaultIssuer: 'https://security.microsoft.com',
    description: 'Microsoft Defender for Endpoint',
    color: 'bg-blue-500',
    events: [
      {
        id: 'threat-detected',
        label: 'Threat Detected',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Active threat detected on device',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Active threat detected on device by Microsoft Defender',
            'Security software detected a threat on your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'suspicious-activity',
        label: 'Suspicious Activity',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Suspicious user or device activity detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Suspicious activity detected by Microsoft Defender',
            'Unusual activity was detected on your account',
            riskLevel,
            context
          ),
      },
      {
        id: 'risky-signin',
        label: 'Risky Sign-In',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'High-risk sign-in attempt detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'High-risk sign-in detected by Microsoft Entra ID Protection',
            'A suspicious sign-in attempt was detected',
            riskLevel,
            context
          ),
      },
      {
        id: 'impossible-travel',
        label: 'Impossible Travel',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Impossible travel activity detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Impossible travel detected: sign-in from geographically distant locations',
            'Unusual sign-in locations were detected',
            riskLevel,
            context
          ),
      },
      {
        id: 'entra-session-revoked',
        label: 'Entra Session Revoked',
        schema: CAEP_SESSION_REVOKED,
        severity: 'high',
        category: 'session',
        experimental: true,
        description: 'Entra ID revokes refresh tokens and sessions for the user (CAEP)',
        buildPayload: (email, timestamp, _riskLevel, context) =>
          buildCaepPayload(
            CAEP_SESSION_REVOKED,
            email,
            timestamp,
            'Microsoft Entra ID revoked all sessions after a confirmed compromised sign-in',
            'Your session was ended for security reasons',
            context
          ),
      },
    ],
  },
  sentinelone: {
    id: 'sentinelone',
    name: 'SentinelOne',
    defaultIssuer: 'https://usea1.sentinelone.net',
    description: 'Autonomous endpoint security platform',
    color: 'bg-purple-600',
    events: [
      {
        id: 'threat-mitigated',
        label: 'Threat Mitigated',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Threat automatically mitigated on endpoint',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Threat automatically mitigated by SentinelOne',
            'A security threat was detected and blocked',
            riskLevel,
            context
          ),
      },
      {
        id: 'malicious-file',
        label: 'Malicious File Detected',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Malicious file identified on endpoint',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Malicious file detected and quarantined by SentinelOne',
            'A harmful file was found on your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'behavioral-ai',
        label: 'Behavioral AI Alert',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Behavioral AI detected suspicious activity',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Behavioral AI detected suspicious activity patterns',
            'Unusual behavior was detected on your device',
            riskLevel,
            context
          ),
      },
    ],
  },
  netskope: {
    id: 'netskope',
    name: 'Netskope',
    defaultIssuer: 'https://addon.goskope.com',
    description: 'Cloud security and SASE platform',
    color: 'bg-teal-600',
    events: [
      {
        id: 'data-exfiltration',
        label: 'Data Exfiltration Attempt',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Potential data exfiltration detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Potential data exfiltration attempt detected by Netskope',
            'Suspicious data transfer activity was detected',
            riskLevel,
            context
          ),
      },
      {
        id: 'risky-app-usage',
        label: 'Risky App Usage',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'User accessing high-risk cloud application',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'User accessing high-risk cloud application detected',
            'Access to a risky application was detected',
            riskLevel,
            context
          ),
      },
      {
        id: 'policy-violation',
        label: 'Cloud Policy Violation',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Cloud security policy violation',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Cloud security policy violation detected by Netskope',
            'A cloud security policy was violated',
            riskLevel,
            context
          ),
      },
    ],
  },
  proofpoint: {
    id: 'proofpoint',
    name: 'Proofpoint',
    defaultIssuer: 'https://tap.proofpoint.com',
    description: 'Email security and threat protection',
    color: 'bg-yellow-600',
    events: [
      {
        id: 'phishing-clicked',
        label: 'Phishing Link Clicked',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'User clicked on phishing link',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'User clicked on known phishing link detected by Proofpoint',
            'You may have clicked on a malicious link',
            riskLevel,
            context
          ),
      },
      {
        id: 'malware-attachment',
        label: 'Malware Attachment',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Malicious email attachment detected',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Malicious email attachment detected by Proofpoint TAP',
            'A harmful email attachment was blocked',
            riskLevel,
            context
          ),
      },
      {
        id: 'bec-attempt',
        label: 'BEC Attempt',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Business email compromise attempt',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Business email compromise (BEC) attempt detected',
            'A suspicious email impersonation was detected',
            riskLevel,
            context
          ),
      },
      {
        id: 'vap-targeted',
        label: 'VAP Targeted',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Very Attacked Person targeted by campaign',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Very Attacked Person (VAP) targeted by threat campaign',
            'Your account has been targeted by attackers',
            riskLevel,
            context
          ),
      },
    ],
  },
  cisco: {
    id: 'cisco',
    name: 'Cisco Secure Endpoint',
    defaultIssuer: 'https://api.amp.cisco.com',
    description: 'Endpoint detection and response',
    color: 'bg-cyan-600',
    events: [
      {
        id: 'malware-executed',
        label: 'Malware Executed',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Malware execution detected on endpoint',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Malware execution detected by Cisco Secure Endpoint',
            'Malicious software was detected running on your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'exploit-prevention',
        label: 'Exploit Prevented',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Exploit attempt blocked',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Exploit attempt prevented by Cisco Secure Endpoint',
            'An attack attempt was blocked on your device',
            riskLevel,
            context
          ),
      },
      {
        id: 'threat-quarantined',
        label: 'Threat Quarantined',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'Threat detected and quarantined',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'Threat detected and quarantined by Cisco Secure Endpoint',
            'A potential threat was isolated on your device',
            riskLevel,
            context
          ),
      },
    ],
  },
  soar: {
    id: 'soar',
    name: 'SOAR / IdP Response (CAEP)',
    defaultIssuer: 'https://soar.example.com',
    description: 'Standards-based CAEP signals from a SOC automation playbook',
    color: 'bg-emerald-600',
    events: [
      {
        id: 'caep-session-revoked',
        label: 'Session Revoked',
        schema: CAEP_SESSION_REVOKED,
        severity: 'high',
        category: 'session',
        experimental: true,
        description: 'SOC playbook kills the attacker session (CAEP session-revoked)',
        buildPayload: (email, timestamp, _riskLevel, context) =>
          buildCaepPayload(
            CAEP_SESSION_REVOKED,
            email,
            timestamp,
            'SOAR playbook revoked session: suspected session hijack',
            'Your session was ended for security reasons',
            context
          ),
      },
      {
        id: 'caep-credential-change',
        label: 'Compromised Password Rotated',
        schema: CAEP_CREDENTIAL_CHANGE,
        severity: 'medium',
        category: 'credential',
        experimental: true,
        description: 'Helpdesk reset a compromised password (CAEP credential-change)',
        buildPayload: (email, timestamp, _riskLevel, context) =>
          buildCaepPayload(
            CAEP_CREDENTIAL_CHANGE,
            email,
            timestamp,
            'Password reset by helpdesk after credential exposure',
            'Your password was reset by your IT team',
            context,
            { credential_type: 'password', change_type: 'update' }
          ),
      },
      {
        id: 'caep-assurance-downgrade',
        label: 'MFA Assurance Downgraded',
        schema: CAEP_ASSURANCE_LEVEL_CHANGE,
        severity: 'medium',
        category: 'session',
        experimental: true,
        description: 'Session assurance dropped from phishing-resistant to password-only (CAEP)',
        buildPayload: (email, timestamp, _riskLevel, context) =>
          buildCaepPayload(
            CAEP_ASSURANCE_LEVEL_CHANGE,
            email,
            timestamp,
            'Authentication assurance downgraded from AAL3 to AAL1',
            'Your sign-in strength changed',
            context,
            {
              namespace: 'NIST-AAL',
              current_level: 'nist-aal1',
              previous_level: 'nist-aal3',
              change_direction: 'decrease',
            }
          ),
      },
      {
        id: 'caep-risk-level-change',
        label: 'Risk Level Change (CAEP)',
        schema: CAEP_RISK_LEVEL_CHANGE,
        severity: 'high',
        category: 'risk',
        experimental: true,
        description: 'Standard CAEP risk-level-change instead of the Okta-proprietary schema',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildCaepRiskLevelPayload(
            email,
            timestamp,
            'SOC correlation engine raised user risk',
            riskLevel,
            context
          ),
      },
    ],
  },
  risc: {
    id: 'risc',
    name: 'RISC Lifecycle',
    defaultIssuer: 'https://my-local-transmitter.com',
    description: 'OpenID RISC lifecycle events',
    color: 'bg-indigo-600',
    events: [
      {
        id: 'risc-session-revoked',
        label: 'Session Revoked',
        schema: RISC_SESSION_REVOKED,
        severity: 'medium',
        category: 'lifecycle',
        description: 'User sessions have been revoked',
        buildPayload: (email, timestamp) =>
          buildLifecyclePayload(email, timestamp, RISC_SESSION_REVOKED),
      },
      {
        id: 'risc-credential-change',
        label: 'Credential Change Required',
        schema: RISC_CREDENTIAL_CHANGE,
        severity: 'high',
        category: 'lifecycle',
        description: 'User must change credentials',
        buildPayload: (email, timestamp) =>
          buildLifecyclePayload(email, timestamp, RISC_CREDENTIAL_CHANGE),
      },
      {
        id: 'risc-account-disabled',
        label: 'Account Disabled',
        schema: RISC_ACCOUNT_DISABLED,
        severity: 'high',
        category: 'lifecycle',
        description: 'User account has been disabled',
        buildPayload: (email, timestamp) =>
          buildLifecyclePayload(email, timestamp, RISC_ACCOUNT_DISABLED),
      },
      {
        id: 'risc-account-credential-change',
        label: 'Account Credential Change Required',
        schema: RISC_ACCOUNT_CREDENTIAL_CHANGE,
        severity: 'high',
        category: 'lifecycle',
        description: 'Account-level credential change required',
        buildPayload: (email, timestamp) =>
          buildLifecyclePayload(email, timestamp, RISC_ACCOUNT_CREDENTIAL_CHANGE),
      },
    ],
  },
  custom: {
    id: 'custom',
    name: 'Custom',
    defaultIssuer: 'https://my-local-transmitter.com',
    description: 'Generic SSF events for testing',
    color: 'bg-gray-600',
    events: [
      {
        id: 'generic-risk',
        label: 'Generic Risk Event',
        schema: OKTA_RISK_SCHEMA,
        severity: 'high',
        category: 'risk',
        description: 'Generic high-risk event for testing ITP',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'External provider reported account compromise',
            'Your account may have been compromised',
            riskLevel,
            context
          ),
      },
      {
        id: 'session-revoked-risk',
        label: 'Session Revoked (Risk)',
        schema: OKTA_RISK_SCHEMA,
        severity: 'medium',
        category: 'risk',
        description: 'User session terminated due to security concern',
        buildPayload: (email, timestamp, riskLevel, context) =>
          buildRiskPayload(
            email,
            timestamp,
            'User session revoked due to security policy',
            'Your session was ended for security reasons',
            riskLevel,
            context
          ),
      },
    ],
  },
};

export const PROVIDER_LIST = Object.values(PROVIDERS);

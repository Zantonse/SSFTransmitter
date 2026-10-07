export type RiskLevel = 'low' | 'medium' | 'high';
export type EventCategory = 'risk' | 'session' | 'credential' | 'lifecycle';

export interface PayloadContext {
  // Last risk level sent for this subject, so escalations report e.g. medium -> high
  previousLevel?: RiskLevel;
  // Scenario-level overrides of the event's default reason text
  reasonAdmin?: string;
  reasonUser?: string;
}

export interface SecurityEvent {
  id: string;
  label: string;
  schema: string;
  severity: RiskLevel;
  description: string;
  category: EventCategory;
  // Not yet confirmed against a live Okta tenant — smoke test before using in a customer demo
  experimental?: boolean;
  buildPayload: (
    email: string,
    timestamp: number,
    riskLevel: RiskLevel,
    context?: PayloadContext
  ) => Record<string, unknown>;
}

export interface SecurityProvider {
  id: string;
  name: string;
  defaultIssuer: string;
  description: string;
  color: string;
  events: SecurityEvent[];
}

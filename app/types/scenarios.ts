import { RiskLevel } from './providers';

export interface ScenarioStep {
  providerId: string;
  eventId: string;
  riskLevel: RiskLevel;
  delayAfterMs: number; // delay after this step (0 for last step)
  // Override the event's default reason text, e.g. to tell an escalating incident story
  reasonAdmin?: string;
  reasonUser?: string;
  // Presenter script: what to say / show in Okta Admin while this step runs
  note?: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  steps: ScenarioStep[];
}

export interface ScenarioExecutionState {
  scenarioId: string;
  currentStep: number;
  stepStatuses: ('pending' | 'sending' | 'success' | 'error')[];
  running: boolean;
}

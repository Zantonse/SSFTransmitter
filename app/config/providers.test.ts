import { describe, expect, it } from 'vitest';
import {
  PROVIDER_LIST,
  OKTA_RISK_SCHEMA,
  CAEP_RISK_LEVEL_CHANGE,
  CAEP_SESSION_REVOKED,
} from './providers';
import { SCENARIOS } from './scenarios';
import { PROVIDERS } from './providers';

const EMAIL = 'jane.doe@example.com';
const TS = 1_700_000_000;

const allEvents = PROVIDER_LIST.flatMap((provider) =>
  provider.events.map((event) => ({ provider, event }))
);

type Claims = Record<string, unknown>;

function claimsOf(payload: Record<string, unknown>, schema: string): Claims {
  expect(Object.keys(payload)).toEqual([schema]);
  return payload[schema] as Claims;
}

describe('event payloads', () => {
  it.each(allEvents.map(({ provider, event }) => [`${provider.id}/${event.id}`, event] as const))(
    '%s matches snapshot',
    (_name, event) => {
      expect(event.buildPayload(EMAIL, TS, 'high')).toMatchSnapshot();
    }
  );

  it('event IDs are unique within each provider', () => {
    for (const provider of PROVIDER_LIST) {
      const ids = provider.events.map((e) => e.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  it('every payload is keyed by the event schema', () => {
    for (const { event } of allEvents) {
      claimsOf(event.buildPayload(EMAIL, TS, 'high'), event.schema);
    }
  });
});

describe('Okta user-risk-change rules', () => {
  const riskEvents = allEvents.filter(({ event }) => event.schema === OKTA_RISK_SCHEMA);

  it.each(riskEvents.map(({ provider, event }) => [`${provider.id}/${event.id}`, event] as const))(
    '%s follows Okta field requirements',
    (_name, event) => {
      const claims = claimsOf(event.buildPayload(EMAIL, TS, 'medium'), OKTA_RISK_SCHEMA);
      expect(claims.initiating_entity).toBe('policy');
      expect(claims.reason_admin).toEqual({ en: expect.any(String) });
      expect(claims.reason_user).toEqual({ en: expect.any(String) });
      expect(claims.subject).toEqual({ user: { format: 'email', email: EMAIL } });
      expect(claims.current_level).toBe('medium');
    }
  );

  it('defaults previous_level to low without context', () => {
    const event = PROVIDERS.crowdstrike.events[0];
    const claims = claimsOf(event.buildPayload(EMAIL, TS, 'high'), OKTA_RISK_SCHEMA);
    expect(claims.previous_level).toBe('low');
  });

  it('uses the tracked previous_level when provided', () => {
    const event = PROVIDERS.crowdstrike.events[0];
    const claims = claimsOf(event.buildPayload(EMAIL, TS, 'high', { previousLevel: 'medium' }), OKTA_RISK_SCHEMA);
    expect(claims.previous_level).toBe('medium');
  });

  it('applies reason overrides', () => {
    const event = PROVIDERS.paloalto.events[0];
    const claims = claimsOf(
      event.buildPayload(EMAIL, TS, 'high', { reasonAdmin: 'Incident #1', reasonUser: 'Signed out' }),
      OKTA_RISK_SCHEMA
    );
    expect(claims.reason_admin).toEqual({ en: 'Incident #1' });
    expect(claims.reason_user).toEqual({ en: 'Signed out' });
  });
});

describe('CAEP payloads', () => {
  it('session-revoked uses the CAEP namespace and email subject', () => {
    const event = PROVIDERS.soar.events.find((e) => e.id === 'caep-session-revoked')!;
    const claims = claimsOf(event.buildPayload(EMAIL, TS, 'high'), CAEP_SESSION_REVOKED);
    expect(CAEP_SESSION_REVOKED).toContain('/secevent/caep/');
    expect(claims.subject).toEqual({ user: { format: 'email', email: EMAIL } });
    expect(claims.initiating_entity).toBe('policy');
  });

  it('risk-level-change uses uppercase CAEP levels and tracked previous level', () => {
    const event = PROVIDERS.soar.events.find((e) => e.id === 'caep-risk-level-change')!;
    const claims = claimsOf(event.buildPayload(EMAIL, TS, 'high', { previousLevel: 'medium' }), CAEP_RISK_LEVEL_CHANGE);
    expect(claims.current_level).toBe('HIGH');
    expect(claims.previous_level).toBe('MEDIUM');
    expect(claims.principal).toBe('USER');
    expect(claims.risk_reason).toEqual(expect.any(String));
  });

  it('marks all CAEP events as experimental until tenant-verified', () => {
    for (const { event } of allEvents) {
      if (event.schema.includes('/secevent/caep/')) {
        expect(event.experimental).toBe(true);
      }
    }
  });
});

describe('scenarios', () => {
  it.each(SCENARIOS.map((s) => [s.id, s] as const))('%s references existing provider events', (_id, scenario) => {
    for (const step of scenario.steps) {
      const event = PROVIDERS[step.providerId]?.events.find((e) => e.id === step.eventId);
      expect(event, `${step.providerId}/${step.eventId}`).toBeDefined();
    }
  });

  it('last step of every scenario has no trailing delay', () => {
    for (const scenario of SCENARIOS) {
      expect(scenario.steps.at(-1)?.delayAfterMs).toBe(0);
    }
  });
});

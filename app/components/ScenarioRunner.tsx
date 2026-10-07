'use client';
import { useState, useRef } from 'react';
import { SCENARIOS } from '../config/scenarios';
import { PROVIDERS } from '../config/providers';
import { Scenario, ScenarioExecutionState } from '../types/scenarios';
import { SecurityEvent, RiskLevel } from '../types/providers';

interface ScenarioRunnerProps {
  disabled: boolean;
  onTransmitStep: (
    providerId: string,
    event: SecurityEvent,
    riskLevel: RiskLevel,
    overrides?: { reasonAdmin?: string; reasonUser?: string }
  ) => Promise<boolean>;
  delayMs?: number;
}

export default function ScenarioRunner({ disabled, onTransmitStep, delayMs }: ScenarioRunnerProps) {
  const [execution, setExecution] = useState<ScenarioExecutionState | null>(null);
  const [customDelay, setCustomDelay] = useState(delayMs || 2000);
  const abortRef = useRef(false);

  const runScenario = async (scenario: Scenario) => {
    abortRef.current = false;
    const state: ScenarioExecutionState = {
      scenarioId: scenario.id,
      currentStep: 0,
      stepStatuses: scenario.steps.map(() => 'pending'),
      running: true,
    };
    setExecution(state);

    for (let i = 0; i < scenario.steps.length; i++) {
      if (abortRef.current) break;

      const step = scenario.steps[i];
      const provider = PROVIDERS[step.providerId];
      const event = provider?.events.find((e) => e.id === step.eventId);

      if (!provider || !event) {
        setExecution((prev) => {
          if (!prev) return prev;
          const statuses = [...prev.stepStatuses];
          statuses[i] = 'error';
          return { ...prev, currentStep: i, stepStatuses: statuses };
        });
        continue;
      }

      // Mark as sending
      setExecution((prev) => {
        if (!prev) return prev;
        const statuses = [...prev.stepStatuses];
        statuses[i] = 'sending';
        return { ...prev, currentStep: i, stepStatuses: statuses };
      });

      // Execute
      const success = await onTransmitStep(step.providerId, event, step.riskLevel, {
        reasonAdmin: step.reasonAdmin,
        reasonUser: step.reasonUser,
      });

      // Mark result
      setExecution((prev) => {
        if (!prev) return prev;
        const statuses = [...prev.stepStatuses];
        statuses[i] = success ? 'success' : 'error';
        return { ...prev, stepStatuses: statuses };
      });

      // Delay before next step (use custom delay override, or step's own delay)
      const delay = step.delayAfterMs > 0 ? customDelay : 0;
      if (delay > 0 && i < scenario.steps.length - 1 && !abortRef.current) {
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    setExecution((prev) => (prev ? { ...prev, running: false } : prev));
  };

  const stopScenario = () => {
    abortRef.current = true;
    setExecution((prev) => (prev ? { ...prev, running: false } : prev));
  };

  const clearExecution = () => {
    setExecution(null);
  };

  const getProviderName = (providerId: string) => PROVIDERS[providerId]?.name || providerId;
  const getEventLabel = (providerId: string, eventId: string) =>
    PROVIDERS[providerId]?.events.find((e) => e.id === eventId)?.label || eventId;

  const riskColor = (level: RiskLevel) => {
    if (level === 'high') return 'var(--severity-high)';
    if (level === 'medium') return 'var(--severity-medium)';
    return 'var(--severity-low)';
  };

  return (
    <div className="scenario-runner">
      {/* Delay Control */}
      <div className="scenario-delay-control">
        <label>Delay between steps:</label>
        <select
          value={customDelay}
          onChange={(e) => setCustomDelay(Number(e.target.value))}
          disabled={execution?.running}
          className="bulk-delay-select"
        >
          <option value={500}>500ms</option>
          <option value={1000}>1s</option>
          <option value={2000}>2s</option>
          <option value={3000}>3s</option>
          <option value={5000}>5s</option>
        </select>
      </div>

      {/* Scenario Cards */}
      <div className="scenario-list">
        {SCENARIOS.map((scenario) => {
          const isActive = execution?.scenarioId === scenario.id;
          const isRunning = isActive && execution?.running;
          const currentNote = isRunning ? scenario.steps[execution.currentStep]?.note : undefined;

          return (
            <div key={scenario.id} className={`scenario-card ${isActive ? 'active' : ''}`}>
              <div className="scenario-card-header">
                <div>
                  <h3 className="scenario-name">{scenario.name}</h3>
                  <p className="scenario-desc">{scenario.description}</p>
                </div>
                <div className="scenario-meta">
                  <span className="scenario-step-count">{scenario.steps.length} events</span>
                </div>
              </div>

              {/* Step Sequence */}
              <div className="scenario-steps">
                {scenario.steps.map((step, idx) => {
                  const stepStatus = isActive ? execution?.stepStatuses[idx] : undefined;
                  return (
                    <div key={idx} className="scenario-step-row">
                      {/* Status indicator */}
                      <div className={`scenario-step-status ${stepStatus || ''}`}>
                        {stepStatus === 'sending' ? (
                          <div className="scenario-spinner" />
                        ) : stepStatus === 'success' ? (
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                        ) : stepStatus === 'error' ? (
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" strokeWidth="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        ) : (
                          <span className="scenario-step-num">{idx + 1}</span>
                        )}
                      </div>
                      {/* Step info */}
                      <div className="scenario-step-info">
                        <span className="scenario-step-provider">{getProviderName(step.providerId)}</span>
                        <span className="scenario-step-event">{getEventLabel(step.providerId, step.eventId)}</span>
                        {step.reasonAdmin && <span className="scenario-step-note">{step.reasonAdmin}</span>}
                      </div>
                      <span className="scenario-step-risk" style={{ background: riskColor(step.riskLevel) }}>
                        {step.riskLevel.toUpperCase()}
                      </span>
                      {/* Connector line */}
                      {idx < scenario.steps.length - 1 && <div className="scenario-connector" />}
                    </div>
                  );
                })}
              </div>

              {currentNote && (
                <div className="scenario-presenter-note">
                  <strong>Presenter:</strong> {currentNote}
                </div>
              )}

              {/* Action */}
              <div className="scenario-actions">
                {isRunning ? (
                  <button onClick={stopScenario} className="btn-secondary text-xs scenario-stop-btn">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>
                    Stop
                  </button>
                ) : isActive && !execution?.running ? (
                  <button onClick={clearExecution} className="btn-ghost text-xs">
                    Clear
                  </button>
                ) : null}
                {!isRunning && (
                  <button
                    onClick={() => runScenario(scenario)}
                    disabled={disabled || (execution?.running && !isActive)}
                    className="btn-primary text-xs scenario-run-btn"
                  >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                    {isActive ? 'Run Again' : 'Run Scenario'}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

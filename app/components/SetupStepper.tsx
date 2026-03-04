'use client';

interface SetupStepperProps {
  completedSteps: Record<string, boolean>;
  onStepClick: (stepId: string) => void;
}

const STEPS = [
  { id: 'configure', label: 'Configure' },
  { id: 'keys', label: 'Generate Keys' },
  { id: 'register', label: 'Register Provider', optional: true },
  { id: 'send', label: 'Send Events' },
];

export default function SetupStepper({ completedSteps, onStepClick }: SetupStepperProps) {
  const currentStepIndex = STEPS.findIndex((step) => !completedSteps[step.id]);

  return (
    <div className="setup-stepper">
      {STEPS.map((step, index) => {
        const isComplete = completedSteps[step.id];
        const isCurrent = index === currentStepIndex;
        const isPreviousComplete = index > 0 && completedSteps[STEPS[index - 1].id];

        return (
          <div key={step.id} className="setup-stepper-item">
            {index > 0 && (
              <div
                className={`setup-stepper-line${isPreviousComplete ? ' complete' : ''}`}
              />
            )}
            <button
              className={`setup-stepper-circle${isComplete ? ' complete' : ''}${isCurrent ? ' current' : ''}`}
              onClick={() => onStepClick(step.id)}
            >
              {isComplete ? (
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={3}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              ) : (
                index + 1
              )}
            </button>
            <span className={`setup-stepper-label${isComplete ? ' complete' : ''}${isCurrent ? ' current' : ''}`}>
              {step.label}
              {step.optional && (
                <span className="setup-stepper-optional">(optional)</span>
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
}

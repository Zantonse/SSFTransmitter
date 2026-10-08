'use client';

import type { ReactNode } from 'react';

interface SectionHelpProps {
  children: ReactNode;
  // What (if anything) to do in Okta Admin for this step
  inOkta?: ReactNode;
}

export default function SectionHelp({ children, inOkta }: SectionHelpProps) {
  return (
    <div className="section-help">
      <svg className="section-help-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="16" x2="12" y2="12" />
        <line x1="12" y1="8" x2="12.01" y2="8" />
      </svg>
      <div>
        <p>{children}</p>
        {inOkta && (
          <p className="section-help-okta">
            <strong>In Okta:</strong> {inOkta}
          </p>
        )}
      </div>
    </div>
  );
}

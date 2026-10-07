'use client';

import { useState, useEffect } from 'react';
import { SecurityEvent, RiskLevel } from '../types/providers';
import CopyButton from './CopyButton';

interface PayloadPreviewProps {
  event: SecurityEvent;
  subjectEmail: string;
  riskLevel: RiskLevel;
  previousLevel?: RiskLevel;
  issuerUrl: string;
  oktaDomain: string;
  onClose: () => void;
  onSend: (customPayload?: Record<string, unknown>) => void;
  loading: boolean;
}

export default function PayloadPreview({
  event,
  subjectEmail,
  riskLevel,
  previousLevel,
  issuerUrl,
  oktaDomain,
  onClose,
  onSend,
  loading,
}: PayloadPreviewProps) {
  const [isEditing, setIsEditing] = useState(false);
  const [editedPayload, setEditedPayload] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);

  // Generate the preview payload (timestamp fixed when the modal opens)
  const [timestamp] = useState(() => Math.floor(Date.now() / 1000));
  const eventsPayload = event.buildPayload(subjectEmail, timestamp, riskLevel, { previousLevel });

  // Construct the full SET structure for preview
  const fullPayload = {
    iss: issuerUrl,
    iat: timestamp,
    jti: '<generated-uuid>',
    aud: `https://${oktaDomain.replace(/^https?:\/\//, '').replace(/-admin\./, '.').replace(/\/$/, '')}`,
    events: eventsPayload,
  };

  const formattedPayload = JSON.stringify(fullPayload, null, 2);

  useEffect(() => {
    setEditedPayload(formattedPayload);
  }, [formattedPayload]);

  const handleEdit = () => {
    setIsEditing(true);
    setParseError(null);
  };

  const handleSave = () => {
    try {
      JSON.parse(editedPayload);
      setParseError(null);
      setIsEditing(false);
    } catch {
      setParseError('Invalid JSON. Please fix the syntax errors.');
    }
  };

  const handleCancel = () => {
    setEditedPayload(formattedPayload);
    setParseError(null);
    setIsEditing(false);
  };

  const handleSend = () => {
    if (isEditing) {
      try {
        const parsed = JSON.parse(editedPayload);
        onSend(parsed.events);
      } catch {
        setParseError('Invalid JSON. Please fix before sending.');
        return;
      }
    } else {
      onSend();
    }
  };

  // Determine the risk level color
  const riskLevelColors: Record<RiskLevel, string> = {
    high: 'var(--severity-high)',
    medium: 'var(--severity-medium)',
    low: 'var(--severity-low)',
  };

  return (
    <div className="payload-modal-overlay" onClick={onClose}>
      <div className="payload-modal" onClick={(e) => e.stopPropagation()}>
        <div className="payload-modal-header">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">Payload Preview</h3>
            <span
              className="text-xs font-bold px-2 py-1 rounded"
              style={{ backgroundColor: riskLevelColors[riskLevel], color: 'white' }}
            >
              {riskLevel.toUpperCase()}
            </span>
          </div>
          <button onClick={onClose} className="payload-modal-close">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="payload-modal-meta">
          <div className="meta-item">
            <span className="meta-label">Event:</span>
            <span className="meta-value">{event.label}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Subject:</span>
            <span className="meta-value">{subjectEmail}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Issuer:</span>
            <span className="meta-value">{issuerUrl}</span>
          </div>
        </div>

        <div className="payload-modal-content">
          {isEditing ? (
            <textarea
              className="payload-editor"
              value={editedPayload}
              onChange={(e) => setEditedPayload(e.target.value)}
              spellCheck={false}
            />
          ) : (
            <pre className="payload-display">{formattedPayload}</pre>
          )}
          {parseError && <div className="payload-error">{parseError}</div>}
        </div>

        <div className="payload-modal-footer">
          <div className="flex items-center gap-2">
            {isEditing ? (
              <>
                <button onClick={handleSave} className="btn-secondary">
                  Save Changes
                </button>
                <button onClick={handleCancel} className="btn-ghost">
                  Cancel
                </button>
              </>
            ) : (
              <>
                <button onClick={handleEdit} className="btn-secondary">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                  </svg>
                  Edit
                </button>
                <CopyButton text={formattedPayload} label="JSON" compact />
              </>
            )}
          </div>
          <button
            onClick={handleSend}
            disabled={loading}
            className="btn-primary flex items-center gap-2"
          >
            {loading ? (
              <>
                <svg className="animate-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 12a9 9 0 11-6.219-8.56" />
                </svg>
                Transmitting...
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="22" y1="2" x2="11" y2="13" />
                  <polygon points="22 2 15 22 11 13 2 9 22 2" />
                </svg>
                Send Event
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

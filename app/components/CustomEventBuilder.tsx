'use client';

import { useState, useEffect } from 'react';
import { RiskLevel } from '../types/providers';
import {
  OKTA_RISK_SCHEMA,
  RISC_SESSION_REVOKED,
  RISC_CREDENTIAL_CHANGE,
  RISC_ACCOUNT_DISABLED,
  CAEP_SESSION_REVOKED,
  CAEP_CREDENTIAL_CHANGE,
  CAEP_ASSURANCE_LEVEL_CHANGE,
  CAEP_RISK_LEVEL_CHANGE,
} from '../config/providers';

interface CustomEventTemplate {
  id: string;
  name: string;
  schema: string;
  riskLevel: RiskLevel;
  adminReason: string;
  userReason: string;
  customFields: string;
}

interface CustomEventBuilderProps {
  subjectEmail: string;
  riskLevel: RiskLevel;
  onSend: (payload: Record<string, unknown>) => Promise<void>;
  loading: boolean;
  disabled: boolean;
}

const SCHEMA_OPTIONS = [
  { value: OKTA_RISK_SCHEMA, label: 'Okta User Risk Change' },
  { value: CAEP_SESSION_REVOKED, label: 'CAEP Session Revoked' },
  { value: CAEP_CREDENTIAL_CHANGE, label: 'CAEP Credential Change' },
  { value: CAEP_ASSURANCE_LEVEL_CHANGE, label: 'CAEP Assurance Level Change' },
  { value: CAEP_RISK_LEVEL_CHANGE, label: 'CAEP Risk Level Change' },
  { value: RISC_SESSION_REVOKED, label: 'RISC Session Revoked (legacy namespace)' },
  { value: RISC_CREDENTIAL_CHANGE, label: 'RISC Credential Change Required' },
  { value: RISC_ACCOUNT_DISABLED, label: 'RISC Account Disabled' },
  { value: 'custom', label: 'Custom Schema URL' },
];

const STORAGE_KEY = 'ssf-custom-templates';

export default function CustomEventBuilder({
  subjectEmail,
  riskLevel: defaultRiskLevel,
  onSend,
  loading,
  disabled,
}: CustomEventBuilderProps) {
  const [schema, setSchema] = useState(SCHEMA_OPTIONS[0].value);
  const [customSchema, setCustomSchema] = useState('');
  const [localRiskLevel, setLocalRiskLevel] = useState<RiskLevel>(defaultRiskLevel);
  const [adminReason, setAdminReason] = useState('Custom security event from SSF Transmitter');
  const [userReason, setUserReason] = useState('A security event was detected on your account');
  const [customFields, setCustomFields] = useState('');
  const [templates, setTemplates] = useState<CustomEventTemplate[]>([]);
  const [templateName, setTemplateName] = useState('');
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [previewMode, setPreviewMode] = useState(false);

  // Load templates from localStorage
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        // localStorage is only readable after mount, so this has to happen in an effect
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setTemplates(JSON.parse(stored));
      } catch {
        // Invalid stored data
      }
    }
  }, []);

  // Save templates to localStorage
  const saveTemplates = (newTemplates: CustomEventTemplate[]) => {
    setTemplates(newTemplates);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(newTemplates));
  };

  const getEffectiveSchema = () => {
    return schema === 'custom' ? customSchema : schema;
  };

  // Fixed timestamp for the on-screen preview; sends use the current time
  const [previewTimestamp] = useState(() => Math.floor(Date.now() / 1000));

  const buildPayload = (timestamp: number): Record<string, unknown> => {
    const effectiveSchema = getEffectiveSchema();

    // Parse custom fields if provided
    let customFieldsObj = {};
    if (customFields.trim()) {
      try {
        customFieldsObj = JSON.parse(customFields);
      } catch {
        // Invalid JSON, ignore
      }
    }

    // Build based on schema type
    if (effectiveSchema.includes('user-risk-change')) {
      return {
        [effectiveSchema]: {
          event_timestamp: timestamp,
          current_level: localRiskLevel,
          previous_level: 'low',
          initiating_entity: 'policy',
          reason_admin: { en: adminReason },
          reason_user: { en: userReason },
          subject: {
            user: {
              format: 'email',
              email: subjectEmail,
            },
          },
          ...customFieldsObj,
        },
      };
    } else if (effectiveSchema === CAEP_RISK_LEVEL_CHANGE) {
      return {
        [effectiveSchema]: {
          event_timestamp: timestamp,
          principal: 'USER',
          current_level: localRiskLevel.toUpperCase(),
          risk_reason: adminReason,
          subject: {
            user: {
              format: 'email',
              email: subjectEmail,
            },
          },
          ...customFieldsObj,
        },
      };
    } else if (effectiveSchema.includes('/secevent/caep/')) {
      // CAEP common claims; add type-specific fields (e.g. credential_type, change_type) via custom fields
      return {
        [effectiveSchema]: {
          event_timestamp: timestamp,
          initiating_entity: 'policy',
          reason_admin: { en: adminReason },
          reason_user: { en: userReason },
          subject: {
            user: {
              format: 'email',
              email: subjectEmail,
            },
          },
          ...customFieldsObj,
        },
      };
    } else {
      // RISC lifecycle or custom schema
      return {
        [effectiveSchema]: {
          subject: {
            subject_type: 'email',
            email: subjectEmail,
          },
          event_timestamp: timestamp,
          ...customFieldsObj,
        },
      };
    }
  };

  const handleSaveTemplate = () => {
    if (!templateName.trim()) return;

    const newTemplate: CustomEventTemplate = {
      id: crypto.randomUUID(),
      name: templateName,
      schema: schema === 'custom' ? customSchema : schema,
      riskLevel: localRiskLevel,
      adminReason,
      userReason,
      customFields,
    };

    saveTemplates([...templates, newTemplate]);
    setTemplateName('');
    setShowSaveDialog(false);
  };

  const handleLoadTemplate = (template: CustomEventTemplate) => {
    const schemaOption = SCHEMA_OPTIONS.find((s) => s.value === template.schema);
    if (schemaOption) {
      setSchema(template.schema);
    } else {
      setSchema('custom');
      setCustomSchema(template.schema);
    }
    setLocalRiskLevel(template.riskLevel);
    setAdminReason(template.adminReason);
    setUserReason(template.userReason);
    setCustomFields(template.customFields);
  };

  const handleDeleteTemplate = (id: string) => {
    saveTemplates(templates.filter((t) => t.id !== id));
  };

  const handleSend = async () => {
    const payload = buildPayload(Math.floor(Date.now() / 1000));
    await onSend(payload);
  };

  const payload = buildPayload(previewTimestamp);

  return (
    <div className="custom-event-builder">
      {/* Templates Section */}
      {templates.length > 0 && (
        <div className="custom-builder-templates">
          <div className="custom-builder-templates-header">
            <span className="text-xs font-medium text-[var(--text-secondary)]">Saved Templates</span>
          </div>
          <div className="custom-builder-templates-list">
            {templates.map((template) => (
              <div key={template.id} className="custom-builder-template-item">
                <button
                  onClick={() => handleLoadTemplate(template)}
                  className="custom-builder-template-btn"
                >
                  {template.name}
                </button>
                <button
                  onClick={() => handleDeleteTemplate(template.id)}
                  className="custom-builder-template-delete"
                  title="Delete template"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Form Fields */}
      <div className="custom-builder-form">
        {/* Schema Selection */}
        <div className="custom-builder-field">
          <label className="custom-builder-label">Event Schema</label>
          <select
            value={schema}
            onChange={(e) => setSchema(e.target.value)}
            className="custom-builder-select"
          >
            {SCHEMA_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        {schema === 'custom' && (
          <div className="custom-builder-field">
            <label className="custom-builder-label">Custom Schema URL</label>
            <input
              type="text"
              value={customSchema}
              onChange={(e) => setCustomSchema(e.target.value)}
              placeholder="https://schemas.example.com/event-type/custom"
              className="custom-builder-input"
            />
          </div>
        )}

        {/* Risk Level */}
        <div className="custom-builder-field">
          <label className="custom-builder-label">Risk Level</label>
          <div className="custom-builder-risk-btns">
            {(['high', 'medium', 'low'] as RiskLevel[]).map((level) => (
              <button
                key={level}
                onClick={() => setLocalRiskLevel(level)}
                className={`custom-builder-risk-btn ${level} ${localRiskLevel === level ? 'active' : ''}`}
              >
                {level.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Admin Reason */}
        <div className="custom-builder-field">
          <label className="custom-builder-label">Admin Reason</label>
          <input
            type="text"
            value={adminReason}
            onChange={(e) => setAdminReason(e.target.value)}
            placeholder="Reason shown to administrators"
            className="custom-builder-input"
          />
        </div>

        {/* User Reason */}
        <div className="custom-builder-field">
          <label className="custom-builder-label">User Reason</label>
          <input
            type="text"
            value={userReason}
            onChange={(e) => setUserReason(e.target.value)}
            placeholder="Reason shown to users"
            className="custom-builder-input"
          />
        </div>

        {/* Custom Fields */}
        <div className="custom-builder-field">
          <label className="custom-builder-label">
            Custom JSON Fields
            <span className="custom-builder-hint">(merged into payload)</span>
          </label>
          <textarea
            value={customFields}
            onChange={(e) => setCustomFields(e.target.value)}
            placeholder={'{\n  "custom_field": "value"\n}'}
            className="custom-builder-textarea"
            rows={3}
          />
        </div>
      </div>

      {/* Preview Toggle */}
      <button
        onClick={() => setPreviewMode(!previewMode)}
        className="custom-builder-preview-toggle"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
        {previewMode ? 'Hide Preview' : 'Show Preview'}
      </button>

      {/* Preview */}
      {previewMode && (
        <div className="custom-builder-preview">
          <pre className="custom-builder-preview-code">
            {JSON.stringify(payload, null, 2)}
          </pre>
        </div>
      )}

      {/* Actions */}
      <div className="custom-builder-actions">
        <button
          onClick={() => setShowSaveDialog(true)}
          className="custom-builder-save-btn"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" />
            <polyline points="17 21 17 13 7 13 7 21" />
            <polyline points="7 3 7 8 15 8" />
          </svg>
          Save Template
        </button>
        <button
          onClick={handleSend}
          disabled={disabled || loading || !getEffectiveSchema()}
          className="btn-primary custom-builder-send-btn"
        >
          {loading ? (
            <>
              <svg className="animate-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12a9 9 0 11-6.219-8.56" />
              </svg>
              Sending...
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

      {/* Save Dialog */}
      {showSaveDialog && (
        <div className="custom-builder-dialog-overlay" onClick={() => setShowSaveDialog(false)}>
          <div className="custom-builder-dialog" onClick={(e) => e.stopPropagation()}>
            <h3 className="custom-builder-dialog-title">Save Template</h3>
            <input
              type="text"
              value={templateName}
              onChange={(e) => setTemplateName(e.target.value)}
              placeholder="Template name"
              className="custom-builder-input"
              autoFocus
            />
            <div className="custom-builder-dialog-actions">
              <button onClick={() => setShowSaveDialog(false)} className="custom-builder-cancel-btn">
                Cancel
              </button>
              <button
                onClick={handleSaveTemplate}
                disabled={!templateName.trim()}
                className="btn-primary"
              >
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

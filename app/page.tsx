'use client';
import { useState, useEffect, useRef } from 'react';
import type { JWK } from 'jose';
import { generateKeyPair } from './utils/crypto';
import { SecurityProvider, SecurityEvent, RiskLevel } from './types/providers';
import { PROVIDERS } from './config/providers';
import ProviderSelector from './components/ProviderSelector';
import EventButtonGrid from './components/EventButtonGrid';
import CopyButton from './components/CopyButton';
import RiskLevelSelector from './components/RiskLevelSelector';
import PayloadPreview from './components/PayloadPreview';
import TransmissionHistory from './components/TransmissionHistory';
import BulkSender from './components/BulkSender';
import CustomEventBuilder from './components/CustomEventBuilder';
import SessionStats from './components/SessionStats';
import ScenarioRunner from './components/ScenarioRunner';
import SetupStepper from './components/SetupStepper';
import { TransmissionRecord } from './types/history';
import { QueuedEvent, BulkSendResult } from './types/bulk';

export default function Home() {
  const [config, setConfig] = useState({
    oktaDomain: '',
    issuerUrl: 'https://my-local-transmitter.com',
    subjectEmail: 'test-user@example.com',
  });

  const [providerId, setProviderId] = useState('crowdstrike');
  const [keys, setKeys] = useState<{ privatePem: string; publicJwk: JWK; kid: string } | null>(null);
  const [logs, setLogs] = useState<{ time: string; message: string; type: 'info' | 'success' | 'error' }[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastPayload, setLastPayload] = useState<Record<string, unknown> | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>('light');
  const [riskLevel, setRiskLevel] = useState<RiskLevel>('high');
  const [previewEvent, setPreviewEvent] = useState<SecurityEvent | null>(null);
  const [history, setHistory] = useState<TransmissionRecord[]>([]);
  const [rightPanelTab, setRightPanelTab] = useState<'log' | 'history' | 'bulk' | 'custom' | 'scenarios'>('log');
  const [bulkQueue, setBulkQueue] = useState<QueuedEvent[]>([]);
  const [configLoaded, setConfigLoaded] = useState(false);
  const sessionStartRef = useRef(Date.now());
  const [jwksUrl, setJwksUrl] = useState('');
  const [jwksVerifyStatus, setJwksVerifyStatus] = useState<{ status: 'idle' | 'loading' | 'valid' | 'error'; message: string }>({ status: 'idle', message: '' });
  const [connectionStatus, setConnectionStatus] = useState<{ status: 'idle' | 'loading' | 'reachable' | 'unreachable'; message: string }>({ status: 'idle', message: '' });
  const [oktaApiToken, setOktaApiToken] = useState('');
  const [showApiToken, setShowApiToken] = useState(false);
  const [providerRegistration, setProviderRegistration] = useState<{
    status: 'idle' | 'loading' | 'success' | 'error';
    providerId?: string;
    providerStatus?: string;
    error?: string;
  }>({ status: 'idle' });
  const [jwksHosted, setJwksHosted] = useState(false);

  const selectedProvider = PROVIDERS[providerId];

  // Derived domain validation
  const domainWarning = (() => {
    const d = config.oktaDomain;
    if (!d) return '';
    if (d.includes('-admin')) return 'Remove "-admin" from the domain — use your base Okta domain instead';
    if (!d.includes('.')) return 'Domain should include TLD (e.g., dev-12345.okta.com)';
    return '';
  })();

  const computedDomain = config.oktaDomain.replace(/-admin/, '').replace(/\/+$/, '');

  // Load persisted config + history from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem('ssf-transmission-history');
    if (stored) {
      try {
        setHistory(JSON.parse(stored));
      } catch {
        // Invalid stored data, ignore
      }
    }

    // Restore persisted configuration
    const savedConfig = localStorage.getItem('ssf-transmitter-config');
    if (savedConfig) {
      try {
        const parsed = JSON.parse(savedConfig);
        if (parsed.oktaDomain || parsed.issuerUrl || parsed.subjectEmail) {
          setConfig({
            oktaDomain: parsed.oktaDomain || '',
            issuerUrl: parsed.issuerUrl || 'https://my-local-transmitter.com',
            subjectEmail: parsed.subjectEmail || 'test-user@example.com',
          });
        }
        if (parsed.providerId && PROVIDERS[parsed.providerId]) {
          setProviderId(parsed.providerId);
        }
        if (parsed.riskLevel && ['low', 'medium', 'high'].includes(parsed.riskLevel)) {
          setRiskLevel(parsed.riskLevel);
        }
        if (parsed.theme && ['dark', 'light'].includes(parsed.theme)) {
          setTheme(parsed.theme);
        }
        if (parsed.jwksUrl) {
          setJwksUrl(parsed.jwksUrl);
        }
        if (parsed.oktaApiToken) {
          setOktaApiToken(parsed.oktaApiToken);
        }
        if (parsed.providerRegistration && parsed.providerRegistration.status === 'success') {
          setProviderRegistration(parsed.providerRegistration);
        }
      } catch {
        // Invalid stored config, ignore
      }
    }
    setConfigLoaded(true);
  }, []);

  // Save history to localStorage when it changes
  useEffect(() => {
    if (history.length > 0) {
      localStorage.setItem('ssf-transmission-history', JSON.stringify(history));
    }
  }, [history]);

  // Persist config to localStorage when it changes (skip initial load)
  useEffect(() => {
    if (!configLoaded) return;
    const saveTimeout = setTimeout(() => {
      localStorage.setItem('ssf-transmitter-config', JSON.stringify({
        oktaDomain: config.oktaDomain,
        issuerUrl: config.issuerUrl,
        subjectEmail: config.subjectEmail,
        providerId,
        riskLevel,
        theme,
        jwksUrl,
        oktaApiToken,
        providerRegistration: providerRegistration.status === 'success' ? providerRegistration : undefined,
      }));
    }, 300);
    return () => clearTimeout(saveTimeout);
  }, [config, providerId, riskLevel, theme, jwksUrl, oktaApiToken, providerRegistration, configLoaded]);

  const clearSavedConfig = () => {
    localStorage.removeItem('ssf-transmitter-config');
    setConfig({ oktaDomain: '', issuerUrl: 'https://my-local-transmitter.com', subjectEmail: 'test-user@example.com' });
    setProviderId('crowdstrike');
    setRiskLevel('high');
    setJwksUrl('');
    setJwksVerifyStatus({ status: 'idle', message: '' });
    setOktaApiToken('');
    setProviderRegistration({ status: 'idle' });
    setJwksHosted(false);
    addLog('Saved configuration cleared', 'info');
  };

  const handleVerifyJwks = async () => {
    if (!jwksUrl || !keys) return;
    setJwksVerifyStatus({ status: 'loading', message: 'Verifying...' });
    try {
      const res = await fetch('/api/verify-jwks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: jwksUrl, expectedKid: keys.kid }),
      });
      const data = await res.json();
      setJwksVerifyStatus({
        status: data.valid ? 'valid' : 'error',
        message: data.message,
      });
    } catch {
      setJwksVerifyStatus({ status: 'error', message: 'Failed to verify — network error' });
    }
  };

  const handleExportConfig = () => {
    const exportData = {
      version: 1,
      oktaDomain: config.oktaDomain,
      issuerUrl: config.issuerUrl,
      subjectEmail: config.subjectEmail,
      selectedProviderId: providerId,
      jwksUrl,
      exportedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ssf-config-${config.oktaDomain || 'untitled'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    addLog('Configuration exported', 'success');
  };

  const handleImportConfig = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target?.result as string);
        if (data.version !== 1) {
          addLog('Unsupported config version', 'error');
          return;
        }
        if (data.oktaDomain) setConfig((prev) => ({ ...prev, oktaDomain: data.oktaDomain }));
        if (data.issuerUrl) setConfig((prev) => ({ ...prev, issuerUrl: data.issuerUrl }));
        if (data.subjectEmail) setConfig((prev) => ({ ...prev, subjectEmail: data.subjectEmail }));
        if (data.selectedProviderId && PROVIDERS[data.selectedProviderId]) {
          setProviderId(data.selectedProviderId);
        }
        if (data.jwksUrl) setJwksUrl(data.jwksUrl);
        addLog(`Loaded config for ${data.oktaDomain || 'unknown'} — generate new keys to begin`, 'success');
      } catch {
        addLog('Invalid config file', 'error');
      }
    };
    reader.readAsText(file);
    // Reset the input so the same file can be re-imported
    e.target.value = '';
  };

  const handleTestConnection = async () => {
    if (!config.oktaDomain) return;
    setConnectionStatus({ status: 'loading', message: 'Testing...' });
    try {
      const res = await fetch('/api/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ oktaDomain: config.oktaDomain }),
      });
      const data = await res.json();
      setConnectionStatus({
        status: data.reachable ? 'reachable' : 'unreachable',
        message: data.message,
      });
    } catch {
      setConnectionStatus({ status: 'unreachable', message: 'Network error' });
    }
  };

  const addHistoryRecord = (record: TransmissionRecord) => {
    setHistory((prev) => [record, ...prev].slice(0, 100)); // Keep last 100 records
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem('ssf-transmission-history');
  };

  // Apply theme class to document root
  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.classList.add('light');
    } else {
      document.documentElement.classList.remove('light');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const addLog = (message: string, type: 'info' | 'success' | 'error' = 'info') => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    setLogs((prev) => [{ time, message, type }, ...prev]);
  };

  const handleGenerateKeys = async () => {
    addLog('Generating RSA-256 key pair...', 'info');
    const result = await generateKeyPair();
    setKeys(result);
    addLog(`Key pair generated. KID: ${result.kid}`, 'success');

    // Auto-push public key to hosted JWKS endpoint
    try {
      const res = await fetch('/api/jwks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kid: result.kid, publicJwk: result.publicJwk }),
      });
      if (res.ok) {
        setJwksHosted(true);
        // Auto-set issuer URL to this app's origin
        setConfig((prev) => ({ ...prev, issuerUrl: window.location.origin }));
        addLog('Public key published to /api/jwks', 'success');
      }
    } catch {
      addLog('Warning: Could not publish key to /api/jwks', 'error');
    }
  };

  // Re-push keys to /api/jwks if keys exist (e.g., after server restart)
  useEffect(() => {
    if (!keys) return;
    fetch('/api/jwks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kid: keys.kid, publicJwk: keys.publicJwk }),
    }).then((res) => {
      if (res.ok) setJwksHosted(true);
    }).catch(() => {});
  }, [keys]);

  const handleCreateProvider = async () => {
    if (!config.oktaDomain || !oktaApiToken) return;
    setProviderRegistration({ status: 'loading' });
    addLog('Registering SSF provider in Okta...', 'info');

    try {
      const appUrl = window.location.origin;
      const res = await fetch('/api/create-provider', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          oktaDomain: config.oktaDomain,
          apiToken: oktaApiToken,
          appUrl,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setProviderRegistration({
          status: 'success',
          providerId: data.providerId,
          providerStatus: data.providerStatus,
        });
        addLog(`Provider registered: ${data.providerId} (${data.providerStatus})`, 'success');
      } else {
        setProviderRegistration({
          status: 'error',
          error: data.errorDescription || data.error,
        });
        addLog(`Provider registration failed: ${data.errorDescription || data.error}`, 'error');
      }
    } catch {
      setProviderRegistration({ status: 'error', error: 'Network error' });
      addLog('Provider registration failed: network error', 'error');
    }
  };

  const handleStepClick = (stepId: string) => {
    const sectionMap: Record<string, string> = {
      configure: 'section-config',
      keys: 'section-keys',
      register: 'section-register',
      send: 'section-transmit',
    };
    const el = document.getElementById(sectionMap[stepId]);
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const completedSteps = {
    configure: Boolean(config.oktaDomain && config.subjectEmail),
    keys: Boolean(keys && jwksHosted),
    register: providerRegistration.status === 'success',
    send: history.length > 0,
  };

  const handleProviderChange = (provider: SecurityProvider) => {
    setProviderId(provider.id);
    setConfig((prev) => ({ ...prev, issuerUrl: provider.defaultIssuer }));
    addLog(`Provider switched to ${provider.name}`, 'info');
  };

  const handleTransmit = async (event: SecurityEvent, overrideRiskLevel?: RiskLevel) => {
    if (!keys || !config.oktaDomain || !config.issuerUrl) {
      addLog('Missing configuration or keys', 'error');
      return;
    }

    const effectiveRiskLevel = overrideRiskLevel || riskLevel;
    setLoading(true);
    setLastPayload(null);
    addLog(`Transmitting ${event.label} via ${selectedProvider.name}...`, 'info');

    try {
      const res = await fetch('/api/transmit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...config,
          privateKeyPem: keys.privatePem,
          keyId: keys.kid,
          providerId,
          eventId: event.id,
          riskLevel: effectiveRiskLevel,
        }),
      });

      const data = await res.json();

      if (data.payload) {
        setLastPayload(data.payload);
      }

      // Create history record
      const historyRecord: TransmissionRecord = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        provider: selectedProvider.name,
        providerId,
        eventType: event.label,
        eventId: event.id,
        userEmail: config.subjectEmail,
        riskLevel: effectiveRiskLevel,
        status: data.success ? 'success' : 'error',
        payload: data.payload || {},
        response: data.success
          ? { status: data.status || 202 }
          : {
              status: data.status || 500,
              error: data.error,
              errorDescription: data.errorDescription,
            },
      };
      addHistoryRecord(historyRecord);

      if (data.success) {
        addLog(`Event transmitted successfully (HTTP ${data.status || 202})`, 'success');
      } else {
        // Log the error with details
        addLog(`Transmission failed: ${data.error || 'Unknown error'}`, 'error');

        if (data.errorDescription) {
          addLog(`Reason: ${data.errorDescription}`, 'error');
        }

        if (data.hint) {
          addLog(`Hint: ${data.hint}`, 'info');
        }

        if (data.debugInfo) {
          addLog(`Issuer: ${data.debugInfo.issuer}`, 'info');
          addLog(`Audience: ${data.debugInfo.audience}`, 'info');
        }
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      addLog(`Network error: ${message}`, 'error');

      // Record failed transmission
      const historyRecord: TransmissionRecord = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        provider: selectedProvider.name,
        providerId,
        eventType: event.label,
        eventId: event.id,
        userEmail: config.subjectEmail,
        riskLevel: effectiveRiskLevel,
        status: 'error',
        payload: {},
        response: { status: 0, error: message },
      };
      addHistoryRecord(historyRecord);
    } finally {
      setLoading(false);
    }
  };

  const handleReplay = (record: TransmissionRecord) => {
    // Find the event in the provider
    const provider = PROVIDERS[record.providerId];
    if (!provider) {
      addLog(`Provider ${record.providerId} not found`, 'error');
      return;
    }

    const event = provider.events.find((e) => e.id === record.eventId);
    if (!event) {
      addLog(`Event ${record.eventId} not found in provider`, 'error');
      return;
    }

    // Switch to the correct provider if needed
    if (providerId !== record.providerId) {
      setProviderId(record.providerId);
    }

    // Replay with the original risk level
    handleTransmit(event, record.riskLevel);
  };

  // Bulk queue management
  const addToQueue = (event: SecurityEvent) => {
    const queueItem: QueuedEvent = {
      id: crypto.randomUUID(),
      providerId,
      providerName: selectedProvider.name,
      eventId: event.id,
      eventLabel: event.label,
      riskLevel,
      status: 'pending',
    };
    setBulkQueue((prev) => [...prev, queueItem]);
    addLog(`Added "${event.label}" to bulk queue`, 'info');
  };

  const removeFromQueue = (id: string) => {
    setBulkQueue((prev) => prev.filter((item) => item.id !== id));
  };

  const clearQueue = () => {
    setBulkQueue([]);
    addLog('Bulk queue cleared', 'info');
  };

  const handleBulkSend = async (delayMs: number): Promise<BulkSendResult> => {
    const pendingItems = bulkQueue.filter((item) => item.status === 'pending');
    let successCount = 0;
    let failedCount = 0;

    addLog(`Starting bulk send of ${pendingItems.length} events...`, 'info');

    for (let i = 0; i < pendingItems.length; i++) {
      const item = pendingItems[i];

      // Update status to sending
      setBulkQueue((prev) =>
        prev.map((q) => (q.id === item.id ? { ...q, status: 'sending' as const } : q))
      );

      // Find the provider and event
      const provider = PROVIDERS[item.providerId];
      const event = provider?.events.find((e) => e.id === item.eventId);

      if (!event || !provider) {
        setBulkQueue((prev) =>
          prev.map((q) =>
            q.id === item.id ? { ...q, status: 'error' as const, error: 'Event not found' } : q
          )
        );
        failedCount++;
        continue;
      }

      try {
        const res = await fetch('/api/transmit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ...config,
            privateKeyPem: keys?.privatePem,
            keyId: keys?.kid,
            providerId: item.providerId,
            eventId: item.eventId,
            riskLevel: item.riskLevel,
          }),
        });

        const data = await res.json();

        if (data.success) {
          setBulkQueue((prev) =>
            prev.map((q) => (q.id === item.id ? { ...q, status: 'success' as const } : q))
          );
          successCount++;

          // Add to history
          const historyRecord: TransmissionRecord = {
            id: crypto.randomUUID(),
            timestamp: Date.now(),
            provider: provider.name,
            providerId: item.providerId,
            eventType: event.label,
            eventId: event.id,
            userEmail: config.subjectEmail,
            riskLevel: item.riskLevel,
            status: 'success',
            payload: data.payload || {},
            response: { status: data.status || 202 },
          };
          addHistoryRecord(historyRecord);
        } else {
          setBulkQueue((prev) =>
            prev.map((q) =>
              q.id === item.id ? { ...q, status: 'error' as const, error: data.error } : q
            )
          );
          failedCount++;

          // Add failed to history
          const historyRecord: TransmissionRecord = {
            id: crypto.randomUUID(),
            timestamp: Date.now(),
            provider: provider.name,
            providerId: item.providerId,
            eventType: event.label,
            eventId: event.id,
            userEmail: config.subjectEmail,
            riskLevel: item.riskLevel,
            status: 'error',
            payload: data.payload || {},
            response: { status: data.status || 500, error: data.error },
          };
          addHistoryRecord(historyRecord);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        setBulkQueue((prev) =>
          prev.map((q) =>
            q.id === item.id ? { ...q, status: 'error' as const, error: message } : q
          )
        );
        failedCount++;
      }

      // Wait before next send (unless it's the last item)
      if (i < pendingItems.length - 1) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }

    addLog(
      `Bulk send complete: ${successCount} succeeded, ${failedCount} failed`,
      failedCount > 0 ? 'error' : 'success'
    );

    return {
      total: pendingItems.length,
      success: successCount,
      failed: failedCount,
    };
  };

  const queuedEventIds = bulkQueue
    .filter((item) => item.providerId === providerId)
    .map((item) => item.eventId);

  // Custom event sender
  const handleCustomEventSend = async (eventPayload: Record<string, unknown>) => {
    if (!keys || !config.oktaDomain || !config.issuerUrl) {
      addLog('Missing configuration or keys', 'error');
      return;
    }

    setLoading(true);
    addLog('Transmitting custom event...', 'info');

    try {
      const res = await fetch('/api/transmit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...config,
          privateKeyPem: keys.privatePem,
          keyId: keys.kid,
          customPayload: eventPayload,
        }),
      });

      const data = await res.json();

      if (data.payload) {
        setLastPayload(data.payload);
      }

      // Create history record
      const schemaUrl = Object.keys(eventPayload)[0] || 'custom';
      const historyRecord: TransmissionRecord = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        provider: 'Custom',
        providerId: 'custom',
        eventType: schemaUrl.split('/').pop() || 'custom-event',
        eventId: 'custom',
        userEmail: config.subjectEmail,
        riskLevel: riskLevel,
        status: data.success ? 'success' : 'error',
        payload: data.payload || eventPayload,
        response: data.success
          ? { status: data.status || 202 }
          : { status: data.status || 500, error: data.error, errorDescription: data.errorDescription },
      };
      addHistoryRecord(historyRecord);

      if (data.success) {
        addLog(`Custom event transmitted successfully (HTTP ${data.status || 202})`, 'success');
      } else {
        addLog(`Transmission failed: ${data.error || 'Unknown error'}`, 'error');
        if (data.errorDescription) {
          addLog(`Reason: ${data.errorDescription}`, 'error');
        }
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      addLog(`Network error: ${message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  // Scenario step handler — sends an event for a specific provider without switching the UI's active provider
  const handleScenarioStep = async (stepProviderId: string, event: SecurityEvent, stepRiskLevel: RiskLevel): Promise<boolean> => {
    if (!keys || !config.oktaDomain || !config.issuerUrl) {
      addLog('Missing configuration or keys', 'error');
      return false;
    }

    const provider = PROVIDERS[stepProviderId];
    addLog(`[Scenario] Sending ${event.label} via ${provider?.name || stepProviderId}...`, 'info');

    try {
      const res = await fetch('/api/transmit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...config,
          privateKeyPem: keys.privatePem,
          keyId: keys.kid,
          providerId: stepProviderId,
          eventId: event.id,
          riskLevel: stepRiskLevel,
        }),
      });

      const data = await res.json();

      // Add history record
      const historyRecord: TransmissionRecord = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        provider: provider?.name || stepProviderId,
        providerId: stepProviderId,
        eventType: event.label,
        eventId: event.id,
        userEmail: config.subjectEmail,
        riskLevel: stepRiskLevel,
        status: data.success ? 'success' : 'error',
        payload: data.payload || {},
        response: data.success
          ? { status: data.status || 202 }
          : { status: data.status || 500, error: data.error },
      };
      addHistoryRecord(historyRecord);

      if (data.success) {
        addLog(`[Scenario] ${event.label} sent successfully`, 'success');
        return true;
      } else {
        addLog(`[Scenario] ${event.label} failed: ${data.error}`, 'error');
        return false;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      addLog(`[Scenario] Network error: ${message}`, 'error');
      return false;
    }
  };

  const providerColorClass = `provider-${providerId}`;

  return (
    <main className="min-h-screen grid-bg">
      {/* Header */}
      <header className="border-b border-[var(--border-default)] bg-[var(--bg-secondary)]">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              {/* Okta Logo */}
              <img
                src="/okta-logo.png"
                alt="Okta"
                className="okta-logo-img"
                height={32}
              />
              <div>
                <h1 className="text-lg font-semibold text-[var(--text-primary)]" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  SSF Transmitter
                </h1>
                <p className="text-xs text-[var(--text-muted)]">Shared Signals Framework for Identity Threat Protection</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="status-dot" />
              <span className="text-xs text-[var(--text-secondary)]">System Ready</span>
            </div>
            <button onClick={toggleTheme} className="theme-toggle" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
              {theme === 'dark' ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="5" />
                  <line x1="12" y1="1" x2="12" y2="3" />
                  <line x1="12" y1="21" x2="12" y2="23" />
                  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                  <line x1="1" y1="12" x2="3" y2="12" />
                  <line x1="21" y1="12" x2="23" y2="12" />
                  <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                  <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                </svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                </svg>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        <SessionStats history={history} sessionStart={sessionStartRef.current} />
        <SetupStepper completedSteps={completedSteps} onStepClick={handleStepClick} />
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          {/* Left Column - Configuration */}
          <div className="lg:col-span-3 space-y-6">
            {/* Configuration Card */}
            <div id="section-config" className="card p-6">
              <div className="flex items-center justify-between mb-5">
                <div className="section-header mb-0">
                  <div className="section-number">01</div>
                  <h2 className="section-title">Configuration</h2>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={handleExportConfig} className="btn-ghost text-xs" title="Export configuration">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                      <polyline points="7 10 12 15 17 10" />
                      <line x1="12" y1="15" x2="12" y2="3" />
                    </svg>
                    Export
                  </button>
                  <label className="btn-ghost text-xs cursor-pointer" title="Import configuration">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                      <polyline points="17 8 12 3 7 8" />
                      <line x1="12" y1="3" x2="12" y2="15" />
                    </svg>
                    Import
                    <input type="file" accept=".json" onChange={handleImportConfig} className="hidden" />
                  </label>
                  <button onClick={clearSavedConfig} className="btn-ghost text-xs" title="Clear saved configuration">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6h14" />
                    </svg>
                    Reset
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div>
                  <label className="block text-sm text-[var(--text-secondary)] mb-2 flex items-center gap-2">
                    <svg width="14" height="14" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <circle cx="50" cy="50" r="50" fill="var(--accent-blue)"/>
                      <circle cx="50" cy="50" r="20" fill="white"/>
                    </svg>
                    Okta Domain
                  </label>
                  <input
                    className={`input-field ${config.oktaDomain ? (domainWarning ? 'input-warning' : 'input-valid') : ''}`}
                    placeholder="dev-12345.okta.com"
                    value={config.oktaDomain}
                    onChange={(e) => {
                      let val = e.target.value;
                      // Auto-strip protocol prefix
                      val = val.replace(/^https?:\/\//, '');
                      // Auto-strip trailing slash
                      val = val.replace(/\/+$/, '');
                      setConfig({ ...config, oktaDomain: val });
                    }}
                  />
                  {config.oktaDomain && (
                    <div className="mt-2 space-y-1">
                      {domainWarning && (
                        <p className="text-xs text-[var(--accent-yellow)] flex items-center gap-1">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                          {domainWarning}
                        </p>
                      )}
                      <p className="text-xs text-[var(--text-muted)]">
                        Audience (aud): <code className="text-[var(--accent-purple)] bg-[var(--bg-tertiary)] px-1 rounded text-[11px]">https://{computedDomain}</code>
                      </p>
                    </div>
                  )}
                </div>

                <ProviderSelector
                  selectedProviderId={providerId}
                  onProviderChange={handleProviderChange}
                />

                <div className="md:col-span-2">
                  <label className="block text-sm text-[var(--text-secondary)] mb-2 flex items-center gap-2">
                    Issuer URL
                    <details className="inline-help">
                      <summary className="inline-help-trigger" title="What is the Issuer URL?">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                      </summary>
                      <div className="inline-help-content">
                        This is the URL you entered when creating the Security Events Push Stream in Okta. It identifies this transmitter. It can be any URL you control — many people use their JWKS hosting URL as the base.
                      </div>
                    </details>
                  </label>
                  <div className="flex gap-2">
                    <input
                      className="input-field flex-1"
                      placeholder="https://my-local-transmitter.com"
                      value={config.issuerUrl}
                      onChange={(e) => setConfig({ ...config, issuerUrl: e.target.value })}
                    />
                    <CopyButton text={config.issuerUrl} label="URL" compact />
                  </div>
                  <p className="text-xs text-[var(--text-muted)] mt-2">Auto-populated when provider changes</p>
                </div>

                <div className="md:col-span-2">
                  <label className="block text-sm text-[var(--text-secondary)] mb-2">Target Subject</label>
                  <input
                    className="input-field"
                    placeholder="user@example.com"
                    value={config.subjectEmail}
                    onChange={(e) => setConfig({ ...config, subjectEmail: e.target.value })}
                  />
                </div>

                {/* Connection Test */}
                <div className="md:col-span-2 flex items-center gap-3">
                  <button
                    onClick={handleTestConnection}
                    disabled={!config.oktaDomain || connectionStatus.status === 'loading'}
                    className="btn-secondary text-xs"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                      <polyline points="22 4 12 14.01 9 11.01" />
                    </svg>
                    {connectionStatus.status === 'loading' ? 'Testing...' : 'Test Connection'}
                  </button>
                  {connectionStatus.status !== 'idle' && connectionStatus.status !== 'loading' && (
                    <span className={`text-xs flex items-center gap-1 ${connectionStatus.status === 'reachable' ? 'text-[var(--accent-green)]' : 'text-[var(--accent-red)]'}`}>
                      {connectionStatus.status === 'reachable' ? (
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
                      ) : (
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                      )}
                      {connectionStatus.message}
                    </span>
                  )}
                </div>

                {/* Okta API Key */}
                <div className="md:col-span-2">
                  <label className="block text-sm text-[var(--text-secondary)] mb-2 flex items-center gap-2">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    Okta API Token
                    <span className="text-[10px] text-[var(--text-muted)] font-normal">(for auto-registering provider)</span>
                  </label>
                  <div className="api-key-wrapper">
                    <input
                      className="input-field"
                      type={showApiToken ? 'text' : 'password'}
                      placeholder="Enter your Okta API token (SSWS)"
                      value={oktaApiToken}
                      onChange={(e) => setOktaApiToken(e.target.value)}
                    />
                    <button
                      className="api-key-toggle"
                      onClick={() => setShowApiToken((prev) => !prev)}
                      title={showApiToken ? 'Hide token' : 'Show token'}
                    >
                      {showApiToken ? (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                      ) : (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                      )}
                    </button>
                  </div>
                  <p className="text-[10px] text-[var(--text-muted)] mt-2 opacity-70">
                    Generate at Okta Admin Console → Security → API → Tokens. Stored in browser only.
                  </p>
                </div>
              </div>
            </div>

            {/* Key Management Card */}
            <div id="section-keys" className="card p-6">
              <div className="flex items-center justify-between mb-5">
                <div className="section-header mb-0">
                  <div className="section-number">02</div>
                  <h2 className="section-title">Key Management</h2>
                </div>
                <button onClick={handleGenerateKeys} className="btn-primary flex items-center gap-2">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
                  </svg>
                  Generate Keys
                </button>
              </div>

              {keys ? (
                <div className="space-y-4">
                  {jwksHosted ? (
                    <div className="alert-success">
                      <span className="alert-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
                      </span>
                      <span className="alert-text">
                        JWKS auto-hosted at <code className="text-[11px] bg-[var(--bg-tertiary)] px-1 rounded">{typeof window !== 'undefined' ? window.location.origin : ''}/api/jwks</code>
                      </span>
                    </div>
                  ) : (
                    <div className="alert-warning">
                      <span className="alert-icon">!</span>
                      <span className="alert-text">Publishing key to JWKS endpoint...</span>
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      <span>Key ID: {keys.kid}</span>
                    </div>
                    <CopyButton text={keys.kid} label="Key ID" />
                  </div>
                  <details className="collapsible-tip">
                    <summary>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                      View JWKS / Manual hosting
                    </summary>
                    <div className="tip-content">
                      <p>The JWKS is auto-hosted by this app. If you need to host it externally instead:</p>
                      <div className="relative mt-2">
                        <textarea
                          readOnly
                          className="jwks-output h-24"
                          value={JSON.stringify({ keys: [keys.publicJwk] }, null, 2)}
                        />
                        <div className="absolute top-2 right-2">
                          <CopyButton
                            text={JSON.stringify({ keys: [keys.publicJwk] }, null, 2)}
                            label="JWKS"
                          />
                        </div>
                      </div>
                    </div>
                  </details>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <div className="w-16 h-16 rounded-full bg-[var(--bg-tertiary)] flex items-center justify-center mb-4">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2">
                      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
                    </svg>
                  </div>
                  <p className="text-sm text-[var(--text-muted)]">No keys generated yet</p>
                  <p className="text-xs text-[var(--text-muted)] mt-1">Click &quot;Generate Keys&quot; to create an RSA key pair</p>
                </div>
              )}
            </div>

            {/* Register Provider Card */}
            <div id="section-register" className="card p-6">
              <div className="flex items-center justify-between mb-5">
                <div className="section-header mb-0">
                  <div className="section-number">03</div>
                  <h2 className="section-title">Register Provider</h2>
                </div>
                <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Optional</span>
              </div>

              {providerRegistration.status === 'success' ? (
                <div className="space-y-3">
                  <div className="provider-registration-status">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
                    <div className="flex-1">
                      <p className="text-sm font-semibold text-[var(--text-primary)]">Provider Registered</p>
                      <p className="text-xs text-[var(--text-muted)]" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                        ID: {providerRegistration.providerId}
                      </p>
                    </div>
                    <span className="provider-status-badge active">{providerRegistration.providerStatus}</span>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <p className="text-xs text-[var(--text-secondary)]">
                    Automatically create a Security Events Provider in Okta using the SSF Receiver API.
                    This registers the app&apos;s well-known URL so Okta can verify signed events.
                  </p>
                  {jwksHosted && (
                    <div className="text-xs text-[var(--text-muted)] space-y-1">
                      <p>Well-known URL: <code className="text-[var(--accent-purple)] bg-[var(--bg-tertiary)] px-1 rounded text-[11px]">{typeof window !== 'undefined' ? window.location.origin : ''}/.well-known/ssf-configuration</code></p>
                    </div>
                  )}
                  {providerRegistration.status === 'error' && (
                    <div className="text-xs text-[var(--accent-red)] bg-[rgba(248,81,73,0.1)] border border-[var(--accent-red)] rounded-lg p-3">
                      {providerRegistration.error}
                    </div>
                  )}
                  <button
                    onClick={handleCreateProvider}
                    disabled={!config.oktaDomain || !oktaApiToken || !keys || !jwksHosted || providerRegistration.status === 'loading'}
                    className="btn-primary flex items-center gap-2 w-full justify-center"
                  >
                    {providerRegistration.status === 'loading' ? (
                      <>
                        <div className="scenario-spinner" />
                        Registering...
                      </>
                    ) : (
                      <>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 5v14M5 12h14" />
                        </svg>
                        Create Provider in Okta
                      </>
                    )}
                  </button>
                  {(!config.oktaDomain || !oktaApiToken || !keys) && (
                    <p className="text-[10px] text-[var(--accent-yellow)] text-center">
                      {!config.oktaDomain ? 'Set Okta domain first' : !oktaApiToken ? 'Add API token in Configuration' : 'Generate keys first'}
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Transmission Card */}
            <div id="section-transmit" className="card p-6">
              <div className="flex items-center justify-between mb-5">
                <div className="section-header mb-0">
                  <div className="section-number">04</div>
                  <h2 className="section-title">Transmission</h2>
                </div>
                <div className="flex items-center gap-4">
                  <RiskLevelSelector
                    selectedLevel={riskLevel}
                    onLevelChange={setRiskLevel}
                  />
                  <div className={`provider-indicator ${providerColorClass}`}>
                    <span style={{ color: 'var(--provider-color)' }}>{selectedProvider.name}</span>
                  </div>
                </div>
              </div>

              <EventButtonGrid
                events={selectedProvider.events}
                loading={loading}
                disabled={!keys}
                queuedEventIds={queuedEventIds}
                onEventClick={handleTransmit}
                onPreviewClick={setPreviewEvent}
                onAddToQueue={addToQueue}
              />

              <p className="text-xs text-[var(--text-muted)] text-center mt-4">
                All events trigger Okta Identity Threat Protection via the user-risk-change schema
              </p>
            </div>

            {/* Payload Viewer */}
            {lastPayload && (
              <div className="card p-6">
                <div className="flex items-center justify-between mb-5">
                  <div className="section-header mb-0">
                    <div className="section-number">05</div>
                    <h2 className="section-title">Last Payload</h2>
                  </div>
                  <CopyButton
                    text={JSON.stringify(lastPayload, null, 2)}
                    label="Payload"
                  />
                </div>
                <div className="json-viewer max-h-80 overflow-auto">
                  <pre className="text-[var(--accent-green)]">{JSON.stringify(lastPayload, null, 2)}</pre>
                </div>
              </div>
            )}
          </div>

          {/* Right Column - Activity Log / History */}
          <div className="lg:col-span-2">
            <div className="card sticky top-6 overflow-hidden">
              {/* Tab Header */}
              <div className="right-panel-tabs">
                <button
                  onClick={() => setRightPanelTab('log')}
                  className={`right-panel-tab ${rightPanelTab === 'log' ? 'active' : ''}`}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                  </svg>
                  Activity Log
                </button>
                <button
                  onClick={() => setRightPanelTab('history')}
                  className={`right-panel-tab ${rightPanelTab === 'history' ? 'active' : ''}`}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  History
                  {history.length > 0 && (
                    <span className="tab-badge">{history.length}</span>
                  )}
                </button>
                <button
                  onClick={() => setRightPanelTab('bulk')}
                  className={`right-panel-tab ${rightPanelTab === 'bulk' ? 'active' : ''}`}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                    <line x1="12" y1="8" x2="12" y2="16" />
                    <line x1="8" y1="12" x2="16" y2="12" />
                  </svg>
                  Bulk
                  {bulkQueue.length > 0 && (
                    <span className="tab-badge">{bulkQueue.length}</span>
                  )}
                </button>
                <button
                  onClick={() => setRightPanelTab('custom')}
                  className={`right-panel-tab ${rightPanelTab === 'custom' ? 'active' : ''}`}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                  </svg>
                  Custom
                </button>
                <button
                  onClick={() => setRightPanelTab('scenarios')}
                  className={`right-panel-tab ${rightPanelTab === 'scenarios' ? 'active' : ''}`}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polygon points="5 3 19 12 5 21 5 3" />
                  </svg>
                  Scenarios
                </button>
              </div>

              {/* Tab Content */}
              <div className="right-panel-content">
                {rightPanelTab === 'log' ? (
                  <div className="log-container h-[500px] overflow-y-auto">
                    {logs.length === 0 ? (
                      <div className="flex flex-col items-center justify-center h-full text-center p-4">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="1.5" className="mb-3 opacity-50">
                          <circle cx="12" cy="12" r="10" />
                          <polyline points="12 6 12 12 16 14" />
                        </svg>
                        <p className="text-sm text-[var(--text-muted)]">Waiting for activity...</p>
                      </div>
                    ) : (
                      logs.map((log, i) => (
                        <div key={i} className={`log-entry ${log.type}`}>
                          <span className="log-timestamp">{log.time}</span>
                          <span className="log-message">{log.message}</span>
                        </div>
                      ))
                    )}
                  </div>
                ) : rightPanelTab === 'history' ? (
                  <div className="h-[500px] overflow-hidden">
                    <TransmissionHistory
                      records={history}
                      onReplay={handleReplay}
                      onClear={clearHistory}
                    />
                  </div>
                ) : rightPanelTab === 'bulk' ? (
                  <div className="h-[500px] overflow-hidden">
                    <BulkSender
                      queue={bulkQueue}
                      onRemoveFromQueue={removeFromQueue}
                      onClearQueue={clearQueue}
                      onSendAll={handleBulkSend}
                      disabled={!keys}
                    />
                  </div>
                ) : rightPanelTab === 'custom' ? (
                  <div className="h-[500px] overflow-hidden">
                    <CustomEventBuilder
                      subjectEmail={config.subjectEmail}
                      riskLevel={riskLevel}
                      onSend={handleCustomEventSend}
                      loading={loading}
                      disabled={!keys}
                    />
                  </div>
                ) : (
                  <div className="h-[500px] overflow-hidden">
                    <ScenarioRunner
                      disabled={!keys}
                      onTransmitStep={handleScenarioStep}
                    />
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-[var(--border-default)] bg-[var(--bg-secondary)] mt-8">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
            <span>Built for</span>
            <div className="flex items-center gap-1">
              <svg width="16" height="16" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="50" cy="50" r="50" fill="var(--accent-blue)"/>
                <circle cx="50" cy="50" r="20" fill="white"/>
              </svg>
              <span className="font-semibold text-[var(--text-secondary)]">Okta Identity Threat Protection</span>
            </div>
          </div>
          <div className="text-xs text-[var(--text-muted)]">
            Shared Signals Framework (SSF) Transmitter
          </div>
        </div>
      </footer>

      {/* Payload Preview Modal */}
      {previewEvent && keys && (
        <PayloadPreview
          event={previewEvent}
          subjectEmail={config.subjectEmail}
          riskLevel={riskLevel}
          issuerUrl={config.issuerUrl}
          oktaDomain={config.oktaDomain}
          loading={loading}
          onClose={() => setPreviewEvent(null)}
          onSend={() => {
            handleTransmit(previewEvent);
            setPreviewEvent(null);
          }}
        />
      )}
    </main>
  );
}

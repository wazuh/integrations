/*
 * Wazuh Case Management Plugin
 * MonitorPage — configure automatic case creation from Wazuh alerts
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  EuiText,
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiFieldNumber,
  EuiSelect,
  EuiSwitch,
  EuiButton,
  EuiButtonEmpty,
  EuiLoadingSpinner,
  EuiHorizontalRule,
  EuiIcon,
} from '@elastic/eui';
import { useServices } from '../app';
import { getMonitorConfig, saveMonitorConfig, runMonitorNow } from '../services/case_api';
import { CASE_PRIORITIES, CASE_CATEGORIES } from '../../common/constants';

export const MonitorPage: React.FC = () => {
  const { http } = useServices();

  const [config, setConfig] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'danger'; message: string } | null>(null);

  const [enabled, setEnabled] = useState(false);
  const [minLevel, setMinLevel] = useState(10);
  const [intervalMinutes, setIntervalMinutes] = useState(5);
  const [defaultPriority, setDefaultPriority] = useState('P2');
  const [defaultCategory, setDefaultCategory] = useState('other');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const cfg = await getMonitorConfig(http);
      setConfig(cfg);
      setEnabled(cfg.enabled ?? false);
      setMinLevel(cfg.min_level ?? 10);
      setIntervalMinutes(cfg.interval_minutes ?? 5);
      setDefaultPriority(cfg.default_priority ?? 'P2');
      setDefaultCategory(cfg.default_category ?? 'other');
    } catch (e: any) {
      setToast({ type: 'danger', message: `Failed to load config: ${e.message}` });
    } finally {
      setLoading(false);
    }
  }, [http]);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    setSaving(true);
    try {
      const updated = await saveMonitorConfig(http, {
        enabled,
        min_level: minLevel,
        interval_minutes: intervalMinutes,
        default_priority: defaultPriority,
        default_category: defaultCategory,
      });
      setConfig(updated);
      setToast({ type: 'success', message: 'Monitor configuration saved.' });
    } catch (e: any) {
      setToast({ type: 'danger', message: `Save failed: ${e.message}` });
    } finally {
      setSaving(false);
    }
  };

  const runNow = async () => {
    if (!enabled) {
      setToast({ type: 'danger', message: 'Enable the monitor first, then save before running.' });
      return;
    }
    setRunning(true);
    try {
      const result = await runMonitorNow(http);
      setToast({ type: 'success', message: `Scan complete — ${result.cases_created} new case(s) created.` });
      load();
    } catch (e: any) {
      setToast({ type: 'danger', message: `Run failed: ${e.message}` });
    } finally {
      setRunning(false);
    }
  };

  const priorityOptions = CASE_PRIORITIES.map((p) => ({ value: p.value, text: p.label }));
  const categoryOptions = CASE_CATEGORIES.map((c) => ({ value: c.value, text: c.label }));

  const SEVERITY_ROWS = [
    { range: '13–15', label: 'Critical', color: 'var(--cm-critical)' },
    { range: '10–12', label: 'High',     color: 'var(--cm-danger)' },
    { range: '7–9',   label: 'Medium',   color: 'var(--cm-warning)' },
    { range: '1–6',   label: 'Low',      color: 'var(--cm-success)' },
  ];

  return (
    <div className="caseManagement__fadeIn">
      {/* ── Header ─────────────────────────────────────────── */}
      <div className="caseManagement__header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 40, height: 40, borderRadius: 'var(--cm-radius)',
            background: 'rgba(29,118,238,0.12)',
            border: '1px solid rgba(29,118,238,0.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>
            <EuiIcon type="clock" size="l" color="var(--cm-primary-light)" />
          </div>
          <div>
            <div className="caseManagement__headerTitle">Auto Case Monitor</div>
            <div style={{ fontSize: 13, color: 'var(--cm-text-secondary)', marginTop: 2 }}>
              Automatically create cases when Wazuh alert <code style={{
                background: 'var(--cm-surface)', border: '1px solid var(--cm-border)',
                borderRadius: 3, padding: '1px 5px', fontSize: 12,
              }}>rule.level</code> meets or exceeds the configured threshold.
            </div>
          </div>
        </div>
        <div className="caseManagement__headerActions">
          <span className={`caseManagement__badge ${enabled ? 'caseManagement__badge--resolved' : 'caseManagement__badge--closed'}`}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: enabled ? 'var(--cm-success)' : 'var(--cm-text-muted)',
              display: 'inline-block',
            }} />
            {enabled ? 'Active' : 'Inactive'}
          </span>
        </div>
      </div>

      {/* ── Toast ──────────────────────────────────────────── */}
      {toast && (
        <>
          <div style={{
            padding: '10px 16px',
            borderRadius: 'var(--cm-radius)',
            border: `1px solid ${toast.type === 'success' ? 'var(--cm-success)' : 'var(--cm-danger)'}`,
            background: toast.type === 'success' ? 'rgba(1,125,115,0.08)' : 'rgba(189,39,30,0.08)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <EuiIcon
                type={toast.type === 'success' ? 'checkInCircleFilled' : 'alert'}
                color={toast.type === 'success' ? 'var(--cm-success)' : 'var(--cm-danger)'}
              />
              <span style={{ fontSize: 13, color: 'var(--cm-text)' }}>{toast.message}</span>
            </div>
            <button
              onClick={() => setToast(null)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--cm-text-muted)', fontSize: 16, lineHeight: 1 }}
            >×</button>
          </div>
          <EuiSpacer size="m" />
        </>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: 60 }}>
          <EuiLoadingSpinner size="xl" />
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* ── Configuration card ──────────────────────── */}
          <div className="caseManagement__detail__section">
            <div className="caseManagement__detail__section__sectionTitle">Configuration</div>

            {/* Enable toggle */}
            <div className="caseManagement__form">
              <EuiFormRow label="Monitor enabled">
                <EuiSwitch
                  label={enabled ? 'Enabled — monitor is active' : 'Disabled — no cases will be created'}
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
              </EuiFormRow>
            </div>

            <EuiSpacer size="m" />

            <EuiFlexGroup gutterSize="m">
              <EuiFlexItem>
                <div className="caseManagement__form">
                  <EuiFormRow
                    label="Minimum rule.level"
                    helpText="Create a case when rule.level ≥ this value (1–15)"
                  >
                    <EuiFieldNumber
                      value={minLevel}
                      min={1}
                      max={15}
                      onChange={(e) => setMinLevel(parseInt(e.target.value, 10) || 10)}
                    />
                  </EuiFormRow>
                </div>
              </EuiFlexItem>
              <EuiFlexItem>
                <div className="caseManagement__form">
                  <EuiFormRow
                    label="Polling interval (minutes)"
                    helpText="How often to scan for new alerts"
                  >
                    <EuiFieldNumber
                      value={intervalMinutes}
                      min={1}
                      max={1440}
                      onChange={(e) => setIntervalMinutes(parseInt(e.target.value, 10) || 5)}
                    />
                  </EuiFormRow>
                </div>
              </EuiFlexItem>
            </EuiFlexGroup>

            <EuiSpacer size="m" />

            <EuiFlexGroup gutterSize="m">
              <EuiFlexItem>
                <div className="caseManagement__form">
                  <EuiFormRow label="Default priority">
                    <EuiSelect
                      options={priorityOptions}
                      value={defaultPriority}
                      onChange={(e) => setDefaultPriority(e.target.value)}
                    />
                  </EuiFormRow>
                </div>
              </EuiFlexItem>
              <EuiFlexItem>
                <div className="caseManagement__form">
                  <EuiFormRow label="Default category">
                    <EuiSelect
                      options={categoryOptions}
                      value={defaultCategory}
                      onChange={(e) => setDefaultCategory(e.target.value)}
                    />
                  </EuiFormRow>
                </div>
              </EuiFlexItem>
            </EuiFlexGroup>

            <EuiSpacer size="m" />

            {/* Severity mapping */}
            <div style={{
              border: '1px solid var(--cm-border)',
              borderLeft: '3px solid var(--cm-primary)',
              borderRadius: 'var(--cm-radius)',
              padding: '12px 16px',
              background: 'var(--cm-surface)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <EuiIcon type="iInCircle" color="var(--cm-primary-light)" size="s" />
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--cm-text)' }}>
                  Automatic severity mapping
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 24px' }}>
                {SEVERITY_ROWS.map((r) => (
                  <div key={r.range} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                    <span style={{ color: 'var(--cm-text-secondary)', fontFamily: 'monospace', fontSize: 12 }}>
                      level {r.range}
                    </span>
                    <span style={{ color: 'var(--cm-text-muted)' }}>→</span>
                    <span style={{
                      color: r.color,
                      fontWeight: 600,
                      padding: '1px 8px',
                      borderRadius: 10,
                      fontSize: 11,
                      background: `${r.color}18`,
                      border: `1px solid ${r.color}40`,
                    }}>{r.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <EuiSpacer size="m" />

            {/* Actions */}
            <EuiFlexGroup gutterSize="s" alignItems="center">
              <EuiFlexItem grow={false}>
                <EuiButton
                  fill
                  onClick={save}
                  isLoading={saving}
                  iconType="save"
                  className="caseManagement__button--primary"
                >
                  Save configuration
                </EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty
                  onClick={runNow}
                  isLoading={running}
                  iconType="play"
                  color="primary"
                >
                  Run scan now
                </EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>
          </div>

          {/* ── Statistics card ─────────────────────────── */}
          {config && (
            <div className="caseManagement__detail__section">
              <div className="caseManagement__detail__section__sectionTitle">Statistics</div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {[
                  {
                    label: 'Cases created (lifetime)',
                    value: (
                      <span style={{ fontSize: 22, fontWeight: 700, color: 'var(--cm-primary-light)' }}>
                        {config.cases_created ?? 0}
                      </span>
                    ),
                  },
                  {
                    label: 'Last scan',
                    value: config.last_run_at
                      ? new Date(config.last_run_at).toLocaleString()
                      : <span style={{ color: 'var(--cm-text-muted)' }}>Never</span>,
                  },
                  {
                    label: 'Last processed alert timestamp',
                    value: config.last_processed_timestamp
                      ? new Date(config.last_processed_timestamp).toLocaleString()
                      : <span style={{ color: 'var(--cm-text-muted)' }}>N/A</span>,
                  },
                ].map((row, i, arr) => (
                  <div key={row.label}>
                    <div style={{
                      display: 'flex', alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 0',
                    }}>
                      <span style={{ fontSize: 13, color: 'var(--cm-text-secondary)', fontWeight: 500 }}>
                        {row.label}
                      </span>
                      <span style={{ fontSize: 13, color: 'var(--cm-text)', fontWeight: 500 }}>
                        {row.value}
                      </span>
                    </div>
                    {i < arr.length - 1 && (
                      <EuiHorizontalRule margin="none" style={{ borderColor: 'var(--cm-border)' }} />
                    )}
                  </div>
                ))}
              </div>

              <EuiHorizontalRule margin="s" style={{ borderColor: 'var(--cm-border)' }} />

              <EuiText size="xs" style={{ color: 'var(--cm-text-muted)' }}>
                Case title format:&nbsp;
                <code style={{
                  background: 'var(--cm-surface)',
                  border: '1px solid var(--cm-border)',
                  borderRadius: 3, padding: '1px 5px', fontSize: 11,
                }}>
                  Wazuh-case-NNNN: &lt;rule.description&gt;
                </code>
                &nbsp;— where NNNN is the auto-incremented 4-digit case number.
              </EuiText>
            </div>
          )}

        </div>
      )}
    </div>
  );
};

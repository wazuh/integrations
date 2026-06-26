/*
 * InvestigationNotes — Free-text analyst scratchpad (DFIR-IRIS inspired)
 */
import React, { useState, useEffect } from 'react';
import { EuiButton, EuiFlexGroup, EuiFlexItem } from '@elastic/eui';

interface Props {
  notes: string;
  onSave: (notes: string) => Promise<void>;
  lastUpdated?: string;
}

export const InvestigationNotes: React.FC<Props> = ({ notes, onSave, lastUpdated }) => {
  const [draft, setDraft] = useState(notes || '');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setDraft(notes || '');
  }, [notes]);

  const handleSave = async () => {
    setSaving(true);
    try {
      await onSave(draft);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } finally {
      setSaving(false);
    }
  };

  const isDirty = draft !== (notes || '');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <textarea
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="Write investigation notes, hypotheses, findings, IOC context..."
        rows={10}
        style={{
          width: '100%',
          background: 'var(--cm-surface-hover)',
          border: `1px solid ${isDirty ? 'var(--cm-primary-light)' : 'var(--cm-border)'}`,
          borderRadius: 8,
          padding: '12px 14px',
          color: 'var(--cm-text)',
          fontSize: 13,
          fontFamily: 'SF Mono, Monaco, Menlo, Consolas, monospace',
          lineHeight: 1.7,
          resize: 'vertical',
          outline: 'none',
          transition: 'border-color 0.2s ease',
          boxSizing: 'border-box',
        }}
      />
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
        <EuiFlexItem>
          {lastUpdated && (
            <span style={{ fontSize: 11, color: '#6B7280' }}>
              Last saved: {new Date(lastUpdated).toLocaleString()}
            </span>
          )}
          {isDirty && (
            <span style={{ fontSize: 11, color: '#F5A623' }}>Unsaved changes</span>
          )}
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            size="s"
            onClick={handleSave}
            isLoading={saving}
            isDisabled={!isDirty}
            style={{
              background: isDirty ? 'var(--cm-primary-light)' : 'var(--cm-surface)',
              border: `1px solid ${isDirty ? 'transparent' : 'var(--cm-border)'}`,
              color: isDirty ? '#fff' : 'var(--cm-text)',
              transition: 'all 0.2s ease',
            }}
          >
            {saved ? '✓ Saved' : 'Save Notes'}
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
    </div>
  );
};

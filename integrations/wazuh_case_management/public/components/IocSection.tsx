/*
 * IocSection — Compact IOC panel for the case detail summary sidebar.
 * Shows IOC type dropdown + value input and lists existing IOCs.
 *
 * Lookup buttons open the relevant threat intelligence portal in a new tab:
 *   • IP Address  → AbuseIPDB  + VirusTotal
 *   • Domain      → VirusTotal
 *   • URL         → VirusTotal
 *   • Hash *      → VirusTotal
 */
import React, { useState, useCallback } from 'react';
import {
  EuiSelect,
  EuiFieldText,
  EuiButtonIcon,
  EuiButtonEmpty,
  EuiFlexGroup,
  EuiFlexItem,
  EuiToolTip,
} from '@elastic/eui';
import { Observable, ObservableType } from '../../common/types';
import { OBSERVABLE_TYPES } from '../../common/constants';

interface Props {
  observables: Observable[];
  onAdd: (obs: { type: ObservableType; value: string; description?: string; is_ioc: boolean }) => Promise<void>;
  onRemove: (id: string) => Promise<void>;
}

const IOC_TYPE_COLORS: Partial<Record<ObservableType, string>> = {
  ip: '#EE3434',
  domain: '#F5A623',
  url: '#F5A623',
  hash_md5: '#9333EA',
  hash_sha1: '#9333EA',
  hash_sha256: '#9333EA',
  email: '#4D9FF5',
  filename: '#00BB7A',
  hostname: '#1D76EE',
  user_account: '#1D76EE',
  process: '#F5A623',
};

// ─── Lookup URL builders ─────────────────────────────────────

function abuseIpDbUrl(ip: string): string {
  return `https://www.abuseipdb.com/check/${ip.trim()}`;
}

/**
 * Extract just the bare hostname from a value that may contain
 * a protocol (http://), path, port, query string, etc.
 * e.g. "http://evil.com/path?x=1" → "evil.com"
 *      "evil.com" → "evil.com"
 */
function extractHostname(value: string): string {
  const trimmed = value.trim();
  try {
    // If it looks like a URL (has a scheme), parse it properly
    if (/^https?:\/\//i.test(trimmed)) {
      return new URL(trimmed).hostname.toLowerCase();
    }
    // Otherwise strip any trailing path/port manually
    return trimmed.split('/')[0].split(':')[0].toLowerCase();
  } catch {
    return trimmed.toLowerCase();
  }
}

function virusTotalUrl(type: ObservableType, value: string): string | null {
  const v = value.trim();
  switch (type) {
    case 'ip':
      // VT GUI path — raw IP, no encoding
      return `https://www.virustotal.com/gui/ip-address/${v}`;
    case 'domain':
      // Extract bare hostname in case user pasted a full URL
      return `https://www.virustotal.com/gui/domain/${extractHostname(v)}`;
    case 'url':
      // VT search accepts the raw URL as a query parameter
      return `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}`;
    case 'hash_md5':
    case 'hash_sha1':
    case 'hash_sha256':
      // Hash is hex — safe to put directly in path
      return `https://www.virustotal.com/gui/file/${v.toLowerCase()}`;
    default:
      return null;
  }
}

/** Open a URL in a new tab securely */
function openExternal(url: string) {
  window.open(url, '_blank', 'noopener,noreferrer');
}

// ─── Component ───────────────────────────────────────────────

export const IocSection: React.FC<Props> = ({ observables, onAdd, onRemove }) => {
  const [type, setType] = useState<ObservableType>('ip');
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');
  const [adding, setAdding] = useState(false);
  const [showForm, setShowForm] = useState(false);

  // Only show observables flagged as IOC
  const iocs = observables.filter((o) => o.is_ioc);

  const handleAdd = useCallback(async () => {
    if (!value.trim()) return;
    setAdding(true);
    try {
      await onAdd({ type, value: value.trim(), description: description.trim() || undefined, is_ioc: true });
      setValue('');
      setDescription('');
      setShowForm(false);
    } finally {
      setAdding(false);
    }
  }, [type, value, description, onAdd]);

  const typeLabel = (t: ObservableType) =>
    OBSERVABLE_TYPES.find((o) => o.value === t)?.label || t;

  return (
    <div>
      {/* IOC list */}
      {iocs.length === 0 && !showForm && (
        <div style={{ fontSize: 12, color: 'var(--cm-text-muted)', fontStyle: 'italic', marginBottom: 8 }}>
          No IOCs added yet.
        </div>
      )}

      {iocs.map((ioc) => {
        const color = IOC_TYPE_COLORS[ioc.type] || 'var(--cm-text-secondary)';
        const vtUrl = virusTotalUrl(ioc.type, ioc.value);
        const hasAbuseIPDB = ioc.type === 'ip';

        return (
          <div
            key={ioc.id}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 10px',
              marginBottom: 6,
              background: 'var(--cm-bg)',
              border: '1px solid var(--cm-border)',
              borderRadius: 6,
              borderLeft: `3px solid ${color}`,
            }}
          >
            {/* Type badge */}
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                color,
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                flexShrink: 0,
                minWidth: 70,
              }}
            >
              {typeLabel(ioc.type)}
            </span>

            {/* Value + description */}
            <div style={{ flex: 1, overflow: 'hidden', minWidth: 0 }}>
              <EuiToolTip content={ioc.description || ioc.value} position="top">
                <span
                  style={{
                    fontSize: 12,
                    fontFamily: 'monospace',
                    color: 'var(--cm-text)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    cursor: 'default',
                    display: 'block',
                  }}
                >
                  {ioc.value}
                </span>
              </EuiToolTip>
              {ioc.description && (
                <span style={{ fontSize: 10, color: 'var(--cm-text-muted)', display: 'block', marginTop: 1 }}>
                  {ioc.description}
                </span>
              )}
            </div>

            {/* Lookup actions */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
              {/* AbuseIPDB — IP only */}
              {hasAbuseIPDB && (
                <EuiToolTip content="Check on AbuseIPDB" position="top">
                  <EuiButtonIcon
                    iconType="popout"
                    size="xs"
                    aria-label="Check on AbuseIPDB"
                    onClick={() => openExternal(abuseIpDbUrl(ioc.value))}
                    style={{ color: '#F5A623' }}
                  />
                </EuiToolTip>
              )}

              {/* VirusTotal — IP, domain, URL, hashes */}
              {vtUrl && (
                <EuiToolTip
                  content={`Check on VirusTotal${ioc.type === 'ip' ? ' (IP reputation)' : ''}`}
                  position="top"
                >
                  <button
                    aria-label="Check on VirusTotal"
                    onClick={() => openExternal(vtUrl)}
                    title="VirusTotal"
                    style={{
                      background: 'none',
                      border: 'none',
                      padding: '2px 4px',
                      cursor: 'pointer',
                      borderRadius: 4,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      opacity: 0.85,
                      transition: 'opacity 0.15s, background 0.15s',
                      lineHeight: 1,
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.opacity = '1';
                      (e.currentTarget as HTMLButtonElement).style.background = 'rgba(26,188,156,0.12)';
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.opacity = '0.85';
                      (e.currentTarget as HTMLButtonElement).style.background = 'none';
                    }}
                  >
                    {/* VirusTotal "VT" logo mark */}
                    <svg width="14" height="14" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <rect width="32" height="32" rx="6" fill="#1ABC9C" />
                      <path d="M7 9h4.5L16 21l4.5-12H25L17.5 27h-3L7 9z" fill="white" />
                      <path d="M13 9h6v3h-6z" fill="white" />
                    </svg>
                  </button>
                </EuiToolTip>
              )}

              {/* Remove */}
              <EuiButtonIcon
                iconType="cross"
                size="xs"
                color="danger"
                aria-label="Remove IOC"
                onClick={() => onRemove(ioc.id)}
              />
            </div>
          </div>
        );
      })}

      {/* Add form */}
      {showForm ? (
        <div
          style={{
            padding: 12,
            background: 'var(--cm-bg)',
            border: '1px solid var(--cm-border)',
            borderRadius: 8,
            marginTop: 6,
          }}
        >
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem grow={false} style={{ minWidth: 130 }}>
              <EuiSelect
                id="ioc-type-select"
                options={OBSERVABLE_TYPES.map((t) => ({ value: t.value, text: t.label }))}
                value={type}
                onChange={(e) => setType(e.target.value as ObservableType)}
                compressed
              />
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiFieldText
                id="ioc-value-input"
                placeholder="e.g. 192.168.1.100"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleAdd(); if (e.key === 'Escape') setShowForm(false); }}
                compressed
                autoFocus
              />
            </EuiFlexItem>
          </EuiFlexGroup>
          <div style={{ marginTop: 8 }}>
            <EuiFieldText
              id="ioc-desc-input"
              placeholder="Description (optional)"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              compressed
              fullWidth
            />
          </div>
          <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" style={{ marginTop: 8 }} responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty size="xs" onClick={() => setShowForm(false)} style={{ color: 'var(--cm-text-secondary)' }}>
                Cancel
              </EuiButtonEmpty>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="xs"
                onClick={handleAdd}
                isLoading={adding}
                disabled={!value.trim()}
                style={{ color: !value.trim() ? undefined : 'var(--cm-primary)', fontWeight: 600 }}
              >
                Add IOC
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
        </div>
      ) : (
        <EuiButtonEmpty
          size="xs"
          iconType="plusInCircle"
          onClick={() => setShowForm(true)}
          style={{ color: 'var(--cm-primary)', paddingLeft: 0, marginTop: 4 }}
        >
          Add IOC
        </EuiButtonEmpty>
      )}
    </div>
  );
};

/*
 * CaseListPage — Main landing page with table/kanban views, filters, search, and auto-refresh
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonGroup,
  EuiLoadingSpinner,
  EuiCallOut,
  EuiSpacer,
  EuiSelect,
  EuiToolTip,
  EuiButtonIcon,
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiModalBody,
  EuiModalFooter,
  EuiFormRow,
  EuiFieldText,
  EuiHorizontalRule,
  EuiIcon,
  CriteriaWithPagination,
} from '@elastic/eui';
import { useHistory } from 'react-router-dom';
import { useServices } from '../app';
import { getCases, getAllCasesForExport } from '../services/case_api';
import { exportCasesToExcel } from '../utils/exportUtils';
import { Case, CaseStatus, CaseListQuery } from '../../common/types';
import { CASE_STATUSES } from '../../common/constants';
import { CaseTable } from '../components/CaseTable';
import { KanbanBoard } from '../components/KanbanBoard';

type ViewMode = 'table' | 'kanban';

// ─── Export date-range presets ────────────────────────────────
interface DateRange { from: string; to: string }

function toLocalDatetimeValue(d: Date): string {
  // Returns "YYYY-MM-DDTHH:mm" for datetime-local inputs (local time, not UTC)
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0);
}
function endOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 23, 59, 59, 999);
}

const EXPORT_PRESETS: Array<{ label: string; icon: string; range: () => DateRange | null }> = [
  {
    label: 'All time',
    icon: 'globe',
    range: () => null,
  },
  {
    label: 'Today',
    icon: 'clock',
    range: () => {
      const now = new Date();
      return { from: startOfDay(now).toISOString(), to: endOfDay(now).toISOString() };
    },
  },
  {
    label: 'Yesterday',
    icon: 'calendar',
    range: () => {
      const d = new Date(); d.setDate(d.getDate() - 1);
      return { from: startOfDay(d).toISOString(), to: endOfDay(d).toISOString() };
    },
  },
  {
    label: 'Last 7 days',
    icon: 'calendar',
    range: () => {
      const to = new Date();
      const from = new Date(); from.setDate(from.getDate() - 6);
      return { from: startOfDay(from).toISOString(), to: endOfDay(to).toISOString() };
    },
  },
  {
    label: 'Last 30 days',
    icon: 'calendar',
    range: () => {
      const to = new Date();
      const from = new Date(); from.setDate(from.getDate() - 29);
      return { from: startOfDay(from).toISOString(), to: endOfDay(to).toISOString() };
    },
  },
  {
    label: 'This month',
    icon: 'calendar',
    range: () => {
      const now = new Date();
      const from = new Date(now.getFullYear(), now.getMonth(), 1);
      return { from: from.toISOString(), to: endOfDay(now).toISOString() };
    },
  },
  {
    label: 'Last month',
    icon: 'calendar',
    range: () => {
      const now = new Date();
      const from = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      const to   = new Date(now.getFullYear(), now.getMonth(), 0);
      return { from: from.toISOString(), to: endOfDay(to).toISOString() };
    },
  },
  {
    label: 'This year',
    icon: 'calendar',
    range: () => {
      const now = new Date();
      const from = new Date(now.getFullYear(), 0, 1);
      return { from: from.toISOString(), to: endOfDay(now).toISOString() };
    },
  },
];

const REFRESH_OPTIONS = [
  { value: '0',   text: 'Off' },
  { value: '10',  text: '10s' },
  { value: '30',  text: '30s' },
  { value: '60',  text: '1m' },
  { value: '300', text: '5m' },
];

export const CaseListPage: React.FC = () => {
  const { http } = useServices();
  const history = useHistory();

  const [cases, setCases] = useState<Case[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('table');

  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [showExportModal, setShowExportModal] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState<string>('All time');
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');
  const [isCustom, setIsCustom] = useState(false);

  // Auto-refresh state
  const [refreshInterval, setRefreshInterval] = useState(0); // seconds; 0 = off
  const [countdown, setCountdown] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastRefreshedRef = useRef<Date>(new Date());

  // Query state
  const [query, setQuery] = useState<CaseListQuery>({
    page: 1,
    per_page: 20,
    sort_field: 'created_at',
    sort_order: 'desc',
  });
  const [searchText, setSearchText] = useState('');
  const [activeStatus, setActiveStatus] = useState<CaseStatus | ''>('');

  const fetchCases = useCallback(async (q: CaseListQuery) => {
    setLoading(true);
    setError(null);
    try {
      const result = await getCases(http, q);
      setCases(result.cases);
      setTotal(result.total);
      lastRefreshedRef.current = new Date();
    } catch (e: any) {
      setError(e.message || 'Failed to load cases');
    } finally {
      setLoading(false);
    }
  }, [http]);

  // Initial + query-change fetch
  useEffect(() => {
    fetchCases(query);
  }, [query, fetchCases]);

  // Auto-refresh interval
  useEffect(() => {
    // Clear existing timers
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (countdownRef.current) clearInterval(countdownRef.current);

    if (refreshInterval <= 0) {
      setCountdown(0);
      return;
    }

    setCountdown(refreshInterval);

    // Countdown ticker (every second)
    countdownRef.current = setInterval(() => {
      setCountdown((c) => (c <= 1 ? refreshInterval : c - 1));
    }, 1000);

    // Actual refresh ticker
    intervalRef.current = setInterval(() => {
      fetchCases(query);
    }, refreshInterval * 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshInterval]);

  // Reset countdown when query changes while auto-refresh is on
  useEffect(() => {
    if (refreshInterval <= 0) return;
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (countdownRef.current) clearInterval(countdownRef.current);
    setCountdown(refreshInterval);
    countdownRef.current = setInterval(() => {
      setCountdown((c) => (c <= 1 ? refreshInterval : c - 1));
    }, 1000);
    intervalRef.current = setInterval(() => {
      fetchCases(query);
    }, refreshInterval * 1000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  const handleManualRefresh = () => {
    fetchCases(query);
    if (refreshInterval > 0) setCountdown(refreshInterval);
  };

  const handleSelectPreset = (label: string) => {
    setSelectedPreset(label);
    setIsCustom(label === 'Custom range');
    if (label === 'Custom range') {
      const now = new Date();
      const weekAgo = new Date(); weekAgo.setDate(weekAgo.getDate() - 6);
      setCustomFrom(toLocalDatetimeValue(startOfDay(weekAgo)));
      setCustomTo(toLocalDatetimeValue(endOfDay(now)));
    }
  };

  const handleExportExcel = async () => {
    setExporting(true);
    setExportError(null);
    try {
      let created_from: string | undefined;
      let created_to: string | undefined;

      if (isCustom) {
        if (!customFrom || !customTo) {
          setExportError('Please set both start and end date/time for custom range.');
          setExporting(false);
          return;
        }
        created_from = new Date(customFrom).toISOString();
        created_to   = new Date(customTo).toISOString();
        if (created_from > created_to) {
          setExportError('Start date must be before end date.');
          setExporting(false);
          return;
        }
      } else {
        const preset = EXPORT_PRESETS.find((p) => p.label === selectedPreset);
        const range = preset?.range();
        if (range) {
          created_from = range.from;
          created_to   = range.to;
        }
      }

      const allCases = await getAllCasesForExport(http, {
        status: query.status,
        search: query.search,
        sort_field: query.sort_field,
        sort_order: query.sort_order,
        created_from,
        created_to,
      });

      if (allCases.length === 0) {
        setExportError('No cases found for the selected date range and filters.');
        setExporting(false);
        return;
      }

      const rangeLabel = isCustom
        ? `${customFrom.slice(0, 10)}_to_${customTo.slice(0, 10)}`
        : selectedPreset.toLowerCase().replace(/\s+/g, '-');
      const filename = `wazuh-cases-${rangeLabel}`;

      exportCasesToExcel(allCases, filename, {
        label: isCustom ? `${customFrom.slice(0, 16)} → ${customTo.slice(0, 16)}` : selectedPreset,
        from: created_from,
        to: created_to,
      });

      setShowExportModal(false);
    } catch (e: any) {
      setExportError(`Export failed: ${e.message || 'Unknown error'}`);
    } finally {
      setExporting(false);
    }
  };

  const handleSearch = useCallback((value: string) => {
    setSearchText(value);
    setQuery((prev) => ({ ...prev, search: value || undefined, page: 1 }));
  }, []);

  const handleStatusFilter = useCallback((status: CaseStatus | '') => {
    setActiveStatus(status);
    setQuery((prev) => ({ ...prev, status: status || undefined, page: 1 }));
  }, []);

  const handleTableChange = useCallback((criteria: CriteriaWithPagination<Case>) => {
    setQuery((prev) => ({
      ...prev,
      page: (criteria.page?.index ?? 0) + 1,
      per_page: criteria.page?.size ?? 20,
      sort_field: (criteria.sort?.field as string) ?? prev.sort_field,
      sort_order: criteria.sort?.direction ?? prev.sort_order,
    }));
  }, []);

  const viewToggleButtons = [
    { id: 'table', label: 'Table' },
    { id: 'kanban', label: 'Kanban' },
  ];

  return (
    <div className="caseManagement__fadeIn">
      {/* Header */}
      <div className="caseManagement__header">
        <div className="caseManagement__headerTitle">
          <span>Case Management</span>
          {!loading && (
            <span style={{ fontSize: 14, fontWeight: 400, color: '#94a3b8', marginLeft: 12 }}>
              {total} case{total !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div className="caseManagement__headerActions">
          {/* Auto-refresh controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {/* Manual refresh button */}
            <EuiToolTip content="Refresh now">
              <EuiButtonIcon
                iconType="refresh"
                aria-label="Refresh"
                onClick={handleManualRefresh}
                isLoading={loading}
                color="text"
                style={{ color: 'var(--cm-text-secondary)' }}
              />
            </EuiToolTip>

            {/* Countdown badge */}
            {refreshInterval > 0 && (
              <span style={{
                fontSize: 11,
                color: countdown <= 5 ? 'var(--cm-warning)' : 'var(--cm-text-secondary)',
                minWidth: 28,
                textAlign: 'right',
                fontVariantNumeric: 'tabular-nums',
              }}>
                {countdown}s
              </span>
            )}

            {/* Interval selector */}
            <EuiSelect
              compressed
              options={REFRESH_OPTIONS}
              value={String(refreshInterval)}
              onChange={(e) => setRefreshInterval(Number(e.target.value))}
              prepend="Refresh"
              style={{
                background: 'var(--cm-surface)',
                color: refreshInterval > 0 ? 'var(--cm-success)' : 'var(--cm-text-secondary)',
                border: '1px solid var(--cm-border)',
                fontSize: 12,
              }}
            />
          </div>

          <EuiButtonGroup
            legend="View mode"
            options={viewToggleButtons}
            idSelected={viewMode}
            onChange={(id) => setViewMode(id as ViewMode)}
            buttonSize="compressed"
          />
          <EuiButton
            iconType="exportAction"
            onClick={() => { setShowExportModal(true); setExportError(null); }}
            style={{
              background: 'var(--cm-surface)',
              border: '1px solid var(--cm-border)',
              color: 'var(--cm-text)',
            }}
          >
            Export Excel
          </EuiButton>
          <EuiButton
            id="create-case-btn"
            fill
            iconType="plusInCircle"
            onClick={() => history.push('/create')}
            className="caseManagement__button--primary"
          >
            Create Case
          </EuiButton>
        </div>
      </div>

      {/* Search & Filters */}
      <EuiFlexGroup gutterSize="m" alignItems="center" wrap>
        <EuiFlexItem grow={3}>
          <EuiFieldSearch
            id="case-search-input"
            placeholder="Search cases..."
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            onSearch={handleSearch}
            fullWidth
            compressed
          />
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />

      {/* Status Filter Chips */}
      <div className="caseManagement__filters">
        <span
          className={`caseManagement__filters__chip ${activeStatus === '' ? 'caseManagement__filters__chip--active' : ''}`}
          onClick={() => handleStatusFilter('')}
          role="button"
          tabIndex={0}
          id="filter-chip-all"
        >
          All
        </span>
        {CASE_STATUSES.map((s) => (
          <span
            key={s.value}
            id={`filter-chip-${s.value}`}
            className={`caseManagement__filters__chip ${activeStatus === s.value ? 'caseManagement__filters__chip--active' : ''}`}
            onClick={() => handleStatusFilter(s.value as CaseStatus)}
            role="button"
            tabIndex={0}
          >
            {s.label}
          </span>
        ))}
      </div>

      {/* Export error */}
      {exportError && (
        <>
          <EuiCallOut
            title={exportError}
            color="warning"
            iconType="alert"
            onDismiss={() => setExportError(null)}
          />
          <EuiSpacer size="s" />
        </>
      )}

      {/* Fetch error */}
      {error && (
        <>
          <EuiCallOut title={error} color="danger" iconType="alert" />
          <EuiSpacer size="m" />
        </>
      )}

      {/* Content */}
      {loading && cases.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 60 }}>
          <EuiLoadingSpinner size="xl" />
        </div>
      ) : viewMode === 'table' ? (
        <CaseTable
          cases={cases}
          total={total}
          page={query.page || 1}
          perPage={query.per_page || 20}
          sortField={query.sort_field || 'created_at'}
          sortDirection={query.sort_order || 'desc'}
          onTableChange={handleTableChange}
          loading={loading}
        />
      ) : (
        <KanbanBoard cases={cases} />
      )}

      {/* ── Export Modal ──────────────────────────────── */}
      {showExportModal && (
        <EuiModal
          onClose={() => setShowExportModal(false)}
          style={{ maxWidth: 520, width: '100%' }}
        >
          <EuiModalHeader>
            <EuiModalHeaderTitle>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <EuiIcon type="exportAction" size="m" color="var(--cm-primary-light)" />
                Export Cases to Excel
              </div>
            </EuiModalHeaderTitle>
          </EuiModalHeader>

          <EuiModalBody>
            {/* Export error inside modal */}
            {exportError && (
              <>
                <div style={{
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid var(--cm-warning)',
                  background: 'rgba(245,166,35,0.08)',
                  fontSize: 13,
                  color: 'var(--cm-text)',
                  display: 'flex', gap: 8, alignItems: 'center',
                }}>
                  <EuiIcon type="alert" color="var(--cm-warning)" size="s" />
                  {exportError}
                </div>
                <EuiSpacer size="s" />
              </>
            )}

            {/* Active filter notice */}
            {(query.status || query.search) && (
              <>
                <div style={{
                  padding: '7px 12px',
                  borderRadius: 6,
                  border: '1px solid var(--cm-border)',
                  background: 'var(--cm-surface)',
                  fontSize: 12,
                  color: 'var(--cm-text-secondary)',
                  display: 'flex', gap: 6, alignItems: 'center',
                }}>
                  <EuiIcon type="filter" size="s" color="var(--cm-primary-light)" />
                  Active filters will be applied:
                  {query.status && <span style={{ color: 'var(--cm-text)', fontWeight: 600 }}>&nbsp;Status: {query.status}</span>}
                  {query.search && <span style={{ color: 'var(--cm-text)', fontWeight: 600 }}>&nbsp;Search: "{query.search}"</span>}
                </div>
                <EuiSpacer size="m" />
              </>
            )}

            {/* Quick presets */}
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
              Quick select
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
              {EXPORT_PRESETS.map((p) => {
                const active = selectedPreset === p.label && !isCustom;
                return (
                  <button
                    key={p.label}
                    onClick={() => handleSelectPreset(p.label)}
                    style={{
                      padding: '9px 8px',
                      borderRadius: 6,
                      border: `1px solid ${active ? 'var(--cm-primary)' : 'var(--cm-border)'}`,
                      background: active ? 'rgba(29,118,238,0.10)' : 'var(--cm-surface)',
                      color: active ? 'var(--cm-primary-light)' : 'var(--cm-text)',
                      fontWeight: active ? 600 : 400,
                      fontSize: 13,
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'all 0.15s',
                    }}
                  >
                    {p.label}
                  </button>
                );
              })}
              {/* Custom range button */}
              <button
                onClick={() => handleSelectPreset('Custom range')}
                style={{
                  padding: '9px 8px',
                  borderRadius: 6,
                  border: `1px solid ${isCustom ? 'var(--cm-primary)' : 'var(--cm-border)'}`,
                  background: isCustom ? 'rgba(29,118,238,0.10)' : 'var(--cm-surface)',
                  color: isCustom ? 'var(--cm-primary-light)' : 'var(--cm-text)',
                  fontWeight: isCustom ? 600 : 400,
                  fontSize: 13,
                  cursor: 'pointer',
                  textAlign: 'center',
                  transition: 'all 0.15s',
                  gridColumn: 'span 1',
                }}
              >
                Custom range
              </button>
            </div>

            {/* Custom date+time range */}
            {isCustom && (
              <>
                <EuiHorizontalRule margin="m" />
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--cm-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                  Custom date &amp; time range
                </div>
                <EuiFlexGroup gutterSize="m">
                  <EuiFlexItem>
                    <EuiFormRow label="From" style={{ fontSize: 13 }}>
                      <input
                        type="datetime-local"
                        value={customFrom}
                        onChange={(e) => setCustomFrom(e.target.value)}
                        style={{
                          width: '100%',
                          padding: '6px 10px',
                          borderRadius: 6,
                          border: '1px solid var(--cm-border)',
                          background: 'var(--cm-surface)',
                          color: 'var(--cm-text)',
                          fontSize: 13,
                          outline: 'none',
                        }}
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiFormRow label="To" style={{ fontSize: 13 }}>
                      <input
                        type="datetime-local"
                        value={customTo}
                        onChange={(e) => setCustomTo(e.target.value)}
                        style={{
                          width: '100%',
                          padding: '6px 10px',
                          borderRadius: 6,
                          border: '1px solid var(--cm-border)',
                          background: 'var(--cm-surface)',
                          color: 'var(--cm-text)',
                          fontSize: 13,
                          outline: 'none',
                        }}
                      />
                    </EuiFormRow>
                  </EuiFlexItem>
                </EuiFlexGroup>
              </>
            )}

            {/* Selected range summary */}
            {!isCustom && selectedPreset !== 'All time' && (() => {
              const preset = EXPORT_PRESETS.find((p) => p.label === selectedPreset);
              const range = preset?.range();
              if (!range) return null;
              return (
                <>
                  <EuiSpacer size="m" />
                  <div style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid var(--cm-border)',
                    background: 'rgba(29,118,238,0.06)',
                    fontSize: 12,
                    color: 'var(--cm-text-secondary)',
                    display: 'flex', gap: 6, alignItems: 'center',
                  }}>
                    <EuiIcon type="calendar" size="s" color="var(--cm-primary-light)" />
                    <span>
                      <span style={{ color: 'var(--cm-text)', fontWeight: 600 }}>{new Date(range.from).toLocaleString()}</span>
                      &nbsp;→&nbsp;
                      <span style={{ color: 'var(--cm-text)', fontWeight: 600 }}>{new Date(range.to).toLocaleString()}</span>
                    </span>
                  </div>
                </>
              );
            })()}
          </EuiModalBody>

          <EuiModalFooter>
            <EuiButtonEmpty onClick={() => setShowExportModal(false)}>
              Cancel
            </EuiButtonEmpty>
            <EuiButton
              fill
              iconType="exportAction"
              onClick={handleExportExcel}
              isLoading={exporting}
              className="caseManagement__button--primary"
            >
              {exporting ? 'Exporting…' : 'Download Excel'}
            </EuiButton>
          </EuiModalFooter>
        </EuiModal>
      )}
    </div>
  );
};

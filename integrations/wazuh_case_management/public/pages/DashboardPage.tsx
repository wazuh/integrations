/*
 * DashboardPage — Analytics overview with metrics, charts, and recent activity
 */
import React, { useState, useEffect, useCallback } from 'react';
import {
  EuiLoadingSpinner,
  EuiCallOut,
  EuiSpacer,
  EuiTitle,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButton,
} from '@elastic/eui';
import { useServices } from '../app';
import { getAnalyticsSummary, getAnalyticsTrends } from '../services/case_api';
import { exportDashboardPdf } from '../utils/exportUtils';
import { AnalyticsSummary, CaseTrend } from '../../common/types';
import { CASE_STATUSES, CASE_SEVERITIES } from '../../common/constants';
import { CaseMetrics } from '../components/CaseMetrics';

export const DashboardPage: React.FC = () => {
  const { http } = useServices();
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [trends, setTrends] = useState<CaseTrend[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [summaryRes, trendsRes] = await Promise.all([
        getAnalyticsSummary(http),
        getAnalyticsTrends(http, 30),
      ]);
      setSummary(summaryRes);
      setTrends(Array.isArray(trendsRes) ? trendsRes : (trendsRes as any)?.trends || []);
    } catch (e: any) {
      setError(e.message || 'Failed to load analytics');
    } finally {
      setLoading(false);
    }
  }, [http]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  if (loading) {
    return <div style={{ textAlign: 'center', padding: 80 }}><EuiLoadingSpinner size="xl" /></div>;
  }

  if (error) {
    return <EuiCallOut title={error} color="danger" iconType="alert" />;
  }

  // Status distribution for chart
  const statusData = CASE_STATUSES.map((s) => ({
    label: s.label,
    value: (summary as any)?.[`${s.value === 'in_progress' ? 'in_progress' : s.value}_cases`] || (summary?.by_severity as any)?.[s.value] || 0,
    color: s.color,
  }));

  // Use direct status count fields
  const statusChartData = [
    { label: 'Open', value: summary?.open_cases || 0, color: '#1D76EE' },
    { label: 'In Progress', value: summary?.in_progress_cases || 0, color: '#4D9FF5' },
    { label: 'Waiting', value: summary?.waiting_cases || 0, color: '#F5A623' },
    { label: 'Resolved', value: summary?.resolved_cases || 0, color: '#00BB7A' },
    { label: 'Closed', value: summary?.closed_cases || 0, color: '#6B7280' },
  ];

  const maxStatusValue = Math.max(...statusChartData.map((d) => d.value), 1);

  // Severity data
  const severityChartData = CASE_SEVERITIES.map((s) => ({
    label: s.label,
    value: (summary?.by_severity as any)?.[s.value] || 0,
    color: s.color,
  }));

  const maxSeverityValue = Math.max(...severityChartData.map((d) => d.value), 1);

  // Trends for sparkline
  const maxTrendValue = Math.max(...trends.map((t) => t.created), 1);

  return (
    <div className="caseManagement__fadeIn">
      <div className="caseManagement__header">
        <div className="caseManagement__headerTitle">
          <span>Analytics Dashboard</span>
        </div>
        <div className="caseManagement__headerActions">
          <span style={{ fontSize: 12, color: 'var(--cm-text-secondary)' }}>
            Today: {summary?.cases_created_today || 0} created, {summary?.cases_closed_today || 0} closed
          </span>
          <EuiButton
            iconType="document"
            onClick={exportDashboardPdf}
            size="s"
            style={{
              background: 'var(--cm-surface)',
              border: '1px solid var(--cm-border)',
              color: 'var(--cm-text)',
            }}
            className="cm-no-print"
          >
            Export PDF
          </EuiButton>
        </div>
      </div>

      {/* Metrics Row */}
      <CaseMetrics summary={summary} loading={false} />

      <EuiSpacer size="l" />

      {/* Charts Row */}
      <EuiFlexGroup gutterSize="l">
        {/* Status Distribution */}
        <EuiFlexItem>
          <div className="caseManagement__card caseManagement__card--no-hover">
            <div className="caseManagement__detail__sectionTitle">Cases by Status</div>
            <div className="caseManagement__chart__bar">
              {statusChartData.map((d) => (
                <div
                  key={d.label}
                  className="caseManagement__chart__barItem"
                  style={{
                    height: `${(d.value / maxStatusValue) * 100}%`,
                    background: `linear-gradient(to top, ${d.color}88, ${d.color})`,
                    minHeight: d.value > 0 ? 8 : 2,
                  }}
                  title={`${d.label}: ${d.value}`}
                />
              ))}
            </div>
            <div className="caseManagement__chart__legend">
              {statusChartData.map((d) => (
                <div key={d.label} className="caseManagement__chart__legendItem">
                  <span className="caseManagement__chart__legendItem__dot" style={{ backgroundColor: d.color }} />
                  {d.label} ({d.value})
                </div>
              ))}
            </div>
          </div>
        </EuiFlexItem>

        {/* Severity Distribution */}
        <EuiFlexItem>
          <div className="caseManagement__card caseManagement__card--no-hover">
            <div className="caseManagement__detail__sectionTitle">Cases by Severity</div>
            <div className="caseManagement__chart__bar">
              {severityChartData.map((d) => (
                <div
                  key={d.label}
                  className="caseManagement__chart__barItem"
                  style={{
                    height: `${(d.value / maxSeverityValue) * 100}%`,
                    background: `linear-gradient(to top, ${d.color}88, ${d.color})`,
                    minHeight: d.value > 0 ? 8 : 2,
                  }}
                  title={`${d.label}: ${d.value}`}
                />
              ))}
            </div>
            <div className="caseManagement__chart__legend">
              {severityChartData.map((d) => (
                <div key={d.label} className="caseManagement__chart__legendItem">
                  <span className="caseManagement__chart__legendItem__dot" style={{ backgroundColor: d.color }} />
                  {d.label} ({d.value})
                </div>
              ))}
            </div>
          </div>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="l" />

      {/* Trend Chart */}
      {trends.length > 0 && (
        <div className="caseManagement__card caseManagement__card--no-hover">
          <div className="caseManagement__detail__sectionTitle">Case Trends (Last 30 Days)</div>
          <div className="caseManagement__chart__bar" style={{ height: 160 }}>
            {trends.map((t, i) => (
              <div
                key={i}
                className="caseManagement__chart__barItem"
                style={{
                  height: `${(t.created / maxTrendValue) * 100}%`,
                  background: 'linear-gradient(to top, #1D76EE88, #1D76EE)',
                  minHeight: t.created > 0 ? 4 : 1,
                }}
                title={`${t.date}: ${t.created} created, ${t.closed} closed`}
              />
            ))}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748b', marginTop: 8 }}>
            <span>{trends[0]?.date}</span>
            <span>{trends[trends.length - 1]?.date}</span>
          </div>
        </div>
      )}
    </div>
  );
};

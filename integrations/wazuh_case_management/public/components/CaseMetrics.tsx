/*
 * CaseMetrics — Dashboard metric cards with gradient backgrounds
 */
import React from 'react';
import { AnalyticsSummary } from '../../common/types';

interface Props {
  summary: AnalyticsSummary | null;
  loading: boolean;
}

function formatDuration(ms: number | null): string {
  if (!ms) return '—';
  const hours = Math.floor(ms / 3600000);
  const minutes = Math.floor((ms % 3600000) / 60000);
  if (hours > 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export const CaseMetrics: React.FC<Props> = ({ summary, loading }) => {
  const metrics = [
    { key: 'total', label: 'Total Cases', value: summary?.total_cases ?? 0, className: 'total' },
    { key: 'open', label: 'Open Cases', value: summary?.open_cases ?? 0, className: 'open' },
    { key: 'progress', label: 'In Progress', value: summary?.in_progress_cases ?? 0, className: 'progress' },
    { key: 'resolved', label: 'Resolved', value: (summary?.resolved_cases ?? 0) + (summary?.closed_cases ?? 0), className: 'resolved' },
    { key: 'mttr', label: 'Avg. Resolution', value: formatDuration(summary?.avg_resolution_time_ms ?? null), className: 'mttr' },
  ];

  return (
    <div className="caseManagement__metrics caseManagement__fadeIn">
      {metrics.map((metric) => (
        <div
          key={metric.key}
          className={`caseManagement__metrics__card caseManagement__metrics__card--${metric.className}`}
          id={`metric-card-${metric.key}`}
        >
          <div className="caseManagement__metrics__card__value">
            {loading ? '...' : metric.value}
          </div>
          <div className="caseManagement__metrics__card__label">{metric.label}</div>
        </div>
      ))}
    </div>
  );
};

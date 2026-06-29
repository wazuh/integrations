/*
 * CaseTable — EuiBasicTable for displaying cases with sorting, selection, and pagination
 */
import React, { useCallback } from 'react';
import {
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiLink,
  EuiHealth,
  CriteriaWithPagination,
  EuiTableSelectionType,
} from '@elastic/eui';
import { useHistory } from 'react-router-dom';
import { Case } from '../../common/types';
import { CaseStatusBadge } from './CaseStatusBadge';
import { CaseSeverityBadge } from './CaseSeverityBadge';
import { TlpBadge } from './TlpBadge';
import { CASE_PRIORITIES } from '../../common/constants';


interface Props {
  cases: Case[];
  total: number;
  page: number;
  perPage: number;
  sortField: string;
  sortDirection: 'asc' | 'desc';
  onTableChange: (criteria: CriteriaWithPagination<Case>) => void;
  selection?: EuiTableSelectionType<Case>;
  loading: boolean;
}

export const CaseTable: React.FC<Props> = ({
  cases,
  total,
  page,
  perPage,
  sortField,
  sortDirection,
  onTableChange,
  selection,
  loading,
}) => {
  const history = useHistory();

  const navigateToCase = useCallback(
    (caseItem: Case) => {
      history.push(`/cases/${caseItem.id}`);
    },
    [history],
  );

  const columns: EuiBasicTableColumn<Case>[] = [
    {
      field: 'case_id',
      name: 'Case ID',
      sortable: true,
      width: '140px',
      render: (caseId: string, item: Case) => (
        <EuiLink
          id={`case-link-${item.id}`}
          onClick={() => navigateToCase(item)}
          className="caseManagement__caseIdCell"
        >
          {caseId}
        </EuiLink>
      ),
    },
    {
      field: 'title',
      name: 'Title',
      sortable: true,
      truncateText: true,
      render: (title: string, item: Case) => (
        <EuiLink
          id={`case-title-${item.id}`}
          onClick={() => navigateToCase(item)}
          color="text"
        >
          {title}
        </EuiLink>
      ),
    },
    {
      field: 'status',
      name: 'Status',
      sortable: true,
      width: '140px',
      render: (status: Case['status']) => <CaseStatusBadge status={status} />,
    },
    {
      field: 'severity',
      name: 'Severity',
      sortable: true,
      width: '130px',
      render: (severity: Case['severity']) => <CaseSeverityBadge severity={severity} />,
    },
    {
      field: 'priority',
      name: 'Priority',
      sortable: true,
      width: '100px',
      render: (priority: string) => {
        const config = CASE_PRIORITIES.find((p) => p.value === priority);
        return (
          <EuiHealth color={config?.color || '#94a3b8'}>
            {config?.value || priority}
          </EuiHealth>
        );
      },
    },
    {
      field: 'tlp',
      name: 'TLP',
      sortable: true,
      width: '110px',
      render: (tlp: any) => tlp ? <TlpBadge tlp={tlp} size="small" /> : <span style={{ color: '#64748b' }}>-</span>,
    },
    {
      field: 'tasks',
      name: 'Tasks',
      width: '80px',
      render: (tasks: any[]) => {
        if (!tasks || tasks.length === 0) return <span style={{ color: '#64748b' }}>-</span>;
        const completed = tasks.filter(t => t.completed).length;
        const allDone = completed === tasks.length;
        return (
          <span style={{ color: allDone ? '#00BB7A' : '#A9AEC4', fontSize: 13, fontWeight: allDone ? 600 : 400 }}>
            {completed}/{tasks.length}
          </span>
        );
      },
    },
    {
      field: 'assignee',
      name: 'Assignee',
      sortable: true,
      width: '140px',
      render: (assignee: string | null) => (
        <span style={{ color: assignee ? '#e2e8f0' : '#64748b' }}>
          {assignee || 'Unassigned'}
        </span>
      ),
    },
    {
      field: 'linked_alerts',
      name: 'Alerts',
      width: '70px',
      render: (alerts: any[]) => (
        <span style={{ color: alerts?.length ? '#f59e0b' : '#64748b' }}>
          {alerts?.length || 0}
        </span>
      ),
    },
    {
      field: 'created_at',
      name: 'Created',
      sortable: true,
      width: '120px',
      render: (date: string) => {
        const d = new Date(date);
        return (
          <span style={{ fontSize: 12, color: '#94a3b8' }}>
            {d.toLocaleDateString()}
          </span>
        );
      },
    },
  ];

  const pagination = {
    pageIndex: page - 1,
    pageSize: perPage,
    totalItemCount: total,
    pageSizeOptions: [10, 20, 50],
  };

  const sorting = {
    sort: {
      field: sortField as keyof Case,
      direction: sortDirection,
    },
  };

  return (
    <div className="caseManagement__table caseManagement__fadeIn">
      <EuiBasicTable
        items={cases}
        columns={columns}
        pagination={pagination}
        sorting={sorting}
        onChange={onTableChange}
        selection={selection}
        loading={loading}
        itemId="id"
        hasActions
        rowProps={(item: Case) => ({
          'data-test-subj': `case-row-${item.id}`,
        })}
        noItemsMessage={
          <div className="caseManagement__empty">
            <div className="caseManagement__empty__title">No cases found</div>
            <div className="caseManagement__empty__description">
              Create your first case to start tracking security incidents.
            </div>
          </div>
        }
      />
    </div>
  );
};

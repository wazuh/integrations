/*
 * KanbanBoard — Visual status board with 5 columns
 */
import React from 'react';
import { Case, CaseStatus } from '../../common/types';
import { CASE_STATUSES } from '../../common/constants';
import { CaseCard } from './CaseCard';

interface Props {
  cases: Case[];
}

export const KanbanBoard: React.FC<Props> = ({ cases }) => {
  const columns: { status: CaseStatus; label: string }[] = CASE_STATUSES.map((s) => ({
    status: s.value as CaseStatus,
    label: s.label,
  }));

  return (
    <div className="caseManagement__kanban caseManagement__fadeIn">
      {columns.map((col) => {
        const columnCases = cases.filter((c) => c.status === col.status);
        return (
          <div
            key={col.status}
            className="caseManagement__kanban__column"
            id={`kanban-column-${col.status}`}
          >
            <div className={`caseManagement__kanban__columnHeader caseManagement__kanban__columnHeader--${col.status}`}>
              <span>{col.label}</span>
              <span className="caseManagement__kanban__columnCount">{columnCases.length}</span>
            </div>
            <div className="caseManagement__kanban__columnBody">
              {columnCases.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 20, color: '#64748b', fontSize: 13 }}>
                  No cases
                </div>
              ) : (
                columnCases.map((c) => <CaseCard key={c.id} caseItem={c} />)
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

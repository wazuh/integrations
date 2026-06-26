/*
 * CaseCard — Summary card for a single case, used in Kanban board
 */
import React from 'react';
import { useHistory } from 'react-router-dom';
import { Case } from '../../common/types';
import { CaseSeverityBadge } from './CaseSeverityBadge';

interface Props {
  caseItem: Case;
}

export const CaseCard: React.FC<Props> = ({ caseItem }) => {
  const history = useHistory();

  return (
    <div
      className="caseManagement__caseCard"
      id={`case-card-${caseItem.id}`}
      data-test-subj={`case-card-${caseItem.id}`}
      onClick={() => history.push(`/cases/${caseItem.id}`)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && history.push(`/cases/${caseItem.id}`)}
    >
      <div className="caseManagement__caseCard__title">{caseItem.title}</div>
      <div className="caseManagement__caseCard__id">{caseItem.case_id}</div>
      <CaseSeverityBadge severity={caseItem.severity} />
      <div className="caseManagement__caseCard__footer">
        <span style={{ fontSize: 11, color: '#94a3b8' }}>
          {caseItem.assignee || 'Unassigned'}
        </span>
        <div className="caseManagement__caseCard__meta">
          {caseItem.linked_alerts?.length > 0 && (
            <span title="Linked alerts">🔔 {caseItem.linked_alerts.length}</span>
          )}
          {caseItem.comments?.length > 0 && (
            <span title="Comments">💬 {caseItem.comments.length}</span>
          )}
        </div>
      </div>
    </div>
  );
};

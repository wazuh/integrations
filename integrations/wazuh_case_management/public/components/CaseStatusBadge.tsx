/*
 * CaseStatusBadge — Renders a colored badge for case status
 */
import React from 'react';
import { CaseStatus } from '../../common/types';
import { CASE_STATUSES } from '../../common/constants';

interface Props {
  status: CaseStatus;
}

export const CaseStatusBadge: React.FC<Props> = ({ status }) => {
  const config = CASE_STATUSES.find((s) => s.value === status);
  const label = config?.label || status;

  return (
    <span className={`caseManagement__badge caseManagement__badge--${status}`}>
      <span className="caseManagement__badge__dot" style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: config?.color, display: 'inline-block' }} />
      {label}
    </span>
  );
};

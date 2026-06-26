/*
 * CaseSeverityBadge — Renders a colored badge for case severity
 */
import React from 'react';
import { CaseSeverity } from '../../common/types';
import { CASE_SEVERITIES } from '../../common/constants';

interface Props {
  severity: CaseSeverity;
}

export const CaseSeverityBadge: React.FC<Props> = ({ severity }) => {
  const config = CASE_SEVERITIES.find((s) => s.value === severity);
  const label = config?.label || severity;

  return (
    <span className={`caseManagement__badge caseManagement__badge--${severity}`}>
      {label}
    </span>
  );
};

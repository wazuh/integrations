/*
 * LinkedAlertsList — Displays alerts linked to a case with unlink option
 */
import React from 'react';
import { EuiButtonIcon } from '@elastic/eui';
import { LinkedAlert } from '../../common/types';

interface Props {
  alerts: LinkedAlert[];
  onUnlink: (alertId: string) => Promise<void>;
}

function getLevelClass(level: number): string {
  if (level >= 10) return 'high';
  if (level >= 5) return 'medium';
  return 'low';
}

export const LinkedAlertsList: React.FC<Props> = ({ alerts, onUnlink }) => {
  if (alerts.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: 16, color: '#64748b', fontSize: 13 }}>
        No alerts linked to this case.
      </div>
    );
  }

  return (
    <div className="caseManagement__alerts">
      {alerts.map((alert) => (
        <div key={alert.alert_id} className="caseManagement__alerts__item">
          <div className="caseManagement__alerts__item__info">
            <div className="caseManagement__alerts__item__rule">
              {alert.rule_description}
            </div>
            <div className="caseManagement__alerts__item__meta">
              <span>Agent: {alert.agent_name} ({alert.agent_id})</span>
              <span>Rule: {alert.rule_id}</span>
              <span className={`caseManagement__alerts__item__level caseManagement__alerts__item__level--${getLevelClass(alert.rule_level)}`}>
                Level {alert.rule_level}
              </span>
            </div>
          </div>
          <EuiButtonIcon
            id={`unlink-alert-${alert.alert_id}`}
            iconType="unlink"
            color="danger"
            size="s"
            aria-label="Unlink alert"
            onClick={() => onUnlink(alert.alert_id)}
          />
        </div>
      ))}
    </div>
  );
};

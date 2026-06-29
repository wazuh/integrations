/*
 * CaseTimeline — Activity timeline for a case showing all actions chronologically
 */
import React from 'react';
import { CaseActivity } from '../../common/types';

interface Props {
  activities: CaseActivity[];
}

const ACTION_LABELS: Record<string, string> = {
  case_created: 'created this case',
  status_changed: 'changed status',
  severity_changed: 'changed severity',
  priority_changed: 'changed priority',
  assigned: 'assigned case',
  unassigned: 'unassigned case',
  comment_added: 'added a comment',
  comment_deleted: 'deleted a comment',
  alert_linked: 'linked an alert',
  alert_unlinked: 'unlinked an alert',
  observable_added: 'added an observable',
  observable_removed: 'removed an observable',
  tag_added: 'added a tag',
  tag_removed: 'removed a tag',
  case_closed: 'closed this case',
  case_reopened: 'reopened this case',
};

function formatTimeAgo(dateStr: string): string {
  const now = new Date();
  const date = new Date(dateStr);
  const diff = now.getTime() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return date.toLocaleDateString();
}

export const CaseTimeline: React.FC<Props> = ({ activities }) => {
  const sortedActivities = [...activities].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );

  if (sortedActivities.length === 0) {
    return (
      <div className="caseManagement__empty" style={{ padding: 30 }}>
        <div className="caseManagement__empty__title">No activity yet</div>
      </div>
    );
  }

  return (
    <div className="caseManagement__timeline">
      {sortedActivities.map((activity) => (
        <div
          key={activity.id}
          className={`caseManagement__timeline__entry caseManagement__timeline__entry--${activity.action}`}
        >
          <div className="caseManagement__timeline__entry__text">
            <strong>{activity.user}</strong>{' '}
            {ACTION_LABELS[activity.action] || activity.action}
            {activity.details?.from && activity.details?.to && (
              <span>
                {' '}from <em>{activity.details.from}</em> to <em>{activity.details.to}</em>
              </span>
            )}
            {activity.details?.assignee && (
              <span> to <strong>{activity.details.assignee}</strong></span>
            )}
          </div>
          <div className="caseManagement__timeline__entry__time">
            {formatTimeAgo(activity.timestamp)}
          </div>
        </div>
      ))}
    </div>
  );
};

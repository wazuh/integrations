/*
 * Wazuh Case Management Plugin
 * Wazuh alert search service — thin wrapper around the alerts search API.
 */

import { HttpSetup } from 'opensearch-dashboards/public';
import { WazuhAlertSearchQuery, WazuhAlertHit } from '../../common/types';
import { searchAlerts } from './case_api';

export interface AlertSearchResult {
  alerts: WazuhAlertHit[];
  total: number;
}

/**
 * Search Wazuh alerts with filtering options.
 * Delegates to the case_api searchAlerts function.
 */
export async function searchWazuhAlerts(
  http: HttpSetup,
  query: WazuhAlertSearchQuery = {}
): Promise<AlertSearchResult> {
  return searchAlerts(http, query);
}

/**
 * Get a human-friendly label for an alert.
 */
export function getAlertLabel(alert: WazuhAlertHit): string {
  const { rule, agent } = alert._source;
  return `[${agent.name}] Rule ${rule.id}: ${rule.description} (Level ${rule.level})`;
}

/**
 * Get the severity color for a rule level.
 * Wazuh rule levels: 0-3 informational, 4-7 low, 8-11 medium, 12-14 high, 15 critical
 */
export function getRuleLevelColor(level: number): string {
  if (level >= 15) return '#ef4444';
  if (level >= 12) return '#f97316';
  if (level >= 8) return '#f59e0b';
  if (level >= 4) return '#22d3ee';
  return '#94a3b8';
}

/**
 * Get a severity label for a rule level.
 */
export function getRuleLevelSeverity(level: number): string {
  if (level >= 15) return 'Critical';
  if (level >= 12) return 'High';
  if (level >= 8) return 'Medium';
  if (level >= 4) return 'Low';
  return 'Info';
}

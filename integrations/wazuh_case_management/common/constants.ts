/*
 * Wazuh Case Management Plugin
 * Shared constants between server and client
 */

// ─── Plugin Identification ────────────────────────────────────
export const PLUGIN_ID = 'wazuhCaseManagement';
export const PLUGIN_NAME = 'Case Management';
export const PLUGIN_DESCRIPTION = 'Security incident case management for Wazuh';

// ─── OpenSearch Index ─────────────────────────────────────────
export const CASE_INDEX = 'wazuh-case-management-cases';
export const CASE_INDEX_PATTERN = 'wazuh-case-management-*';
export const CASE_COUNTER_INDEX = 'wazuh-case-management-counter';
export const MONITOR_CONFIG_INDEX = 'wazuh-case-management-monitor';

// ─── Wazuh Alert Index ────────────────────────────────────────
export const WAZUH_ALERTS_INDEX_PATTERN = 'wazuh-alerts-*';

// ─── API Routes ───────────────────────────────────────────────
export const API_PREFIX = '/api/wazuh-case-management';

export const API_ROUTES = {
  // Cases
  CASES: `${API_PREFIX}/cases`,
  CASE_BY_ID: `${API_PREFIX}/cases/{id}`,
  CASE_STATUS: `${API_PREFIX}/cases/{id}/status`,
  CASE_ASSIGN: `${API_PREFIX}/cases/{id}/assign`,

  // Comments
  CASE_COMMENTS: `${API_PREFIX}/cases/{id}/comments`,
  CASE_COMMENT_BY_ID: `${API_PREFIX}/cases/{id}/comments/{commentId}`,

  // Alerts
  CASE_ALERTS: `${API_PREFIX}/cases/{id}/alerts`,
  CASE_ALERT_BY_ID: `${API_PREFIX}/cases/{id}/alerts/{alertId}`,
  ALERTS_SEARCH: `${API_PREFIX}/alerts/search`,

  // Observables
  CASE_OBSERVABLES: `${API_PREFIX}/cases/{id}/observables`,
  CASE_OBSERVABLE_BY_ID: `${API_PREFIX}/cases/{id}/observables/{observableId}`,

  // Analytics
  ANALYTICS_SUMMARY: `${API_PREFIX}/analytics/summary`,
  ANALYTICS_TRENDS: `${API_PREFIX}/analytics/trends`,

  // Settings
  SETTINGS: `${API_PREFIX}/settings`,

  // Users
  ME: `${API_PREFIX}/me`,
  USERS: `${API_PREFIX}/users`,

  // Auto Monitor
  MONITOR: `${API_PREFIX}/monitor`,
  MONITOR_STATUS: `${API_PREFIX}/monitor/status`,
} as const;

// ─── Case ID Configuration ───────────────────────────────────
export const CASE_ID_PREFIX = 'CASE';
export const CASE_ID_SEPARATOR = '-';

// ─── Status Definitions ──────────────────────────────────────
export const CASE_STATUSES = [
  { value: 'open', label: 'Open', color: '#1D76EE', icon: 'folderOpen' },
  { value: 'in_progress', label: 'In Progress', color: '#4D9FF5', icon: 'playFilled' },
  { value: 'waiting', label: 'Waiting', color: '#F5A623', icon: 'clock' },
  { value: 'resolved', label: 'Resolved', color: '#00BB7A', icon: 'checkInCircleFilled' },
  { value: 'closed', label: 'Closed', color: '#6b7280', icon: 'cross' },
] as const;

// Valid status transitions
export const STATUS_TRANSITIONS: Record<string, string[]> = {
  open: ['in_progress', 'waiting', 'closed'],
  in_progress: ['waiting', 'resolved', 'closed'],
  waiting: ['in_progress', 'resolved', 'closed'],
  resolved: ['closed', 'in_progress'], // can reopen
  closed: ['open'], // can reopen
};

// ─── Severity Definitions ────────────────────────────────────
export const CASE_SEVERITIES = [
  { value: 'informational', label: 'Informational', color: '#A9AEC4', order: 0 },
  { value: 'low', label: 'Low', color: '#00BB7A', order: 1 },
  { value: 'medium', label: 'Medium', color: '#F5A623', order: 2 },
  { value: 'high', label: 'High', color: '#EE3434', order: 3 },
  { value: 'critical', label: 'Critical', color: '#9333EA', order: 4 },
] as const;

// ─── Priority Definitions ────────────────────────────────────
export const CASE_PRIORITIES = [
  { value: 'P1', label: 'P1 — Urgent', color: '#ef4444', order: 0 },
  { value: 'P2', label: 'P2 — High', color: '#f97316', order: 1 },
  { value: 'P3', label: 'P3 — Medium', color: '#f59e0b', order: 2 },
  { value: 'P4', label: 'P4 — Low', color: '#94a3b8', order: 3 },
] as const;

// ─── Category Definitions ────────────────────────────────────
export const CASE_CATEGORIES = [
  { value: 'malware', label: 'Malware', icon: 'bug' },
  { value: 'intrusion_attempt', label: 'Intrusion Attempt', icon: 'lock' },
  { value: 'data_exfiltration', label: 'Data Exfiltration', icon: 'exportAction' },
  { value: 'policy_violation', label: 'Policy Violation', icon: 'alert' },
  { value: 'vulnerability', label: 'Vulnerability', icon: 'securitySignal' },
  { value: 'phishing', label: 'Phishing', icon: 'email' },
  { value: 'denial_of_service', label: 'Denial of Service', icon: 'offline' },
  { value: 'insider_threat', label: 'Insider Threat', icon: 'user' },
  { value: 'unauthorized_access', label: 'Unauthorized Access', icon: 'crossInACircleFilled' },
  { value: 'other', label: 'Other', icon: 'questionInCircle' },
] as const;

// ─── Observable Type Definitions ─────────────────────────────
export const OBSERVABLE_TYPES = [
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'hash_md5', label: 'Hash (MD5)' },
  { value: 'hash_sha1', label: 'Hash (SHA-1)' },
  { value: 'hash_sha256', label: 'Hash (SHA-256)' },
  { value: 'email', label: 'Email Address' },
  { value: 'filename', label: 'Filename' },
  { value: 'hostname', label: 'Hostname' },
  { value: 'port', label: 'Port' },
  { value: 'registry_key', label: 'Registry Key' },
  { value: 'user_account', label: 'User Account' },
  { value: 'process', label: 'Process' },
  { value: 'other', label: 'Other' },
] as const;

// ─── Pagination Defaults ─────────────────────────────────────
export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;
export const DEFAULT_SORT_FIELD = 'created_at';
export const DEFAULT_SORT_ORDER = 'desc';

// ─── UI Theme Colors ─────────────────────────────────────────
export const THEME = {
  background: '#1D1E24',
  surface: '#25263A',
  surfaceHover: '#2E2F42',
  border: '#3D3E5A',
  primary: '#1D76EE',
  primaryLight: '#4D9FF5',
  primaryDark: '#1558B0',
  success: '#00BB7A',
  warning: '#F5A623',
  danger: '#EE3434',
  critical: '#9333EA',
  info: '#4D9FF5',
  textPrimary: '#FFFFFF',
  textSecondary: '#A9AEC4',
  textMuted: '#6B7280',
} as const;

// ─── TLP Definitions ─────────────────────────────────────────
export const TLP_LEVELS = [
  { value: 'WHITE', label: 'TLP:WHITE', color: '#FFFFFF', bg: 'rgba(255,255,255,0.1)' },
  { value: 'GREEN', label: 'TLP:GREEN', color: '#00BB7A', bg: 'rgba(0,187,122,0.15)' },
  { value: 'AMBER', label: 'TLP:AMBER', color: '#F5A623', bg: 'rgba(245,166,35,0.15)' },
  { value: 'RED',   label: 'TLP:RED',   color: '#EE3434', bg: 'rgba(238,52,52,0.15)' },
] as const;
